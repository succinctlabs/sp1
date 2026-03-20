// RDNA-optimized NTT for KoalaBear field (31-bit prime)
// Uses Stockham auto-sort to eliminate bit-reversal passes
// Fuses multiple butterfly stages into LDS to minimize global memory traffic
#pragma once

#include <cstdint>
#ifdef __HIPCC__
#include <hip/hip_runtime.h>
#endif

// KoalaBear field Montgomery multiplication
// a, b in Montgomery form -> returns a*b in Montgomery form
__device__ __forceinline__ uint32_t kb_mont_mul(uint32_t a, uint32_t b) {
    uint64_t prod = (uint64_t)a * b;
    uint32_t lo = (uint32_t)prod;
    uint32_t hi = (uint32_t)(prod >> 32);
    uint32_t q = lo * 0x7effffffu; // lo * (-MOD^{-1} mod 2^32)
    uint64_t qm = (uint64_t)q * 0x7f000001u + lo;
    uint32_t r = (uint32_t)(qm >> 32) + hi;
    return r >= 0x7f000001u ? r - 0x7f000001u : r;
}

__device__ __forceinline__ uint32_t kb_add(uint32_t a, uint32_t b) {
    uint32_t r = a + b;
    return r >= 0x7f000001u ? r - 0x7f000001u : r;
}

__device__ __forceinline__ uint32_t kb_sub(uint32_t a, uint32_t b) {
    return a >= b ? a - b : a + 0x7f000001u - b;
}

// Butterfly: (a, b, w) -> (a + w*b, a - w*b)
__device__ __forceinline__ void kb_butterfly(uint32_t& a, uint32_t& b, uint32_t w) {
    uint32_t wb = kb_mont_mul(w, b);
    uint32_t s = kb_add(a, wb);
    uint32_t d = kb_sub(a, wb);
    a = s;
    b = d;
}

// ================================================================
// Stockham NTT: processes LG_LDS_STAGES stages in LDS
// Uses ping-pong between two LDS buffers
// Each thread handles ELTS_PER_THREAD elements
// ================================================================

// Padded index to avoid LDS bank conflicts (32 banks, 4-byte words)
// Pad every 32nd element by 1
#define LDS_PAD(i) ((i) + ((i) >> 5))

// Inner kernel: process multiple stages entirely in LDS
// Template parameters:
//   LDS_STAGES: number of stages to process in LDS (e.g., 10 = 1024 elements)
//   ELTS_PER_THREAD: elements per thread (2, 4, or 8)
template<int LDS_STAGES, int ELTS_PER_THREAD = 2>
__global__ __launch_bounds__(512)
void rdna_stockham_lds_kernel(
    uint32_t* __restrict__ d_out,
    const uint32_t* __restrict__ d_in,
    const uint32_t* __restrict__ root_table,  // primitive root powers
    uint32_t lg_n,
    uint32_t outer_stage  // which group of LDS_STAGES we're processing
) {
    constexpr uint32_t LDS_SIZE = 1u << LDS_STAGES;
    constexpr uint32_t THREADS = LDS_SIZE / ELTS_PER_THREAD;
    constexpr uint32_t PADDED_LDS = LDS_SIZE + (LDS_SIZE >> 5);

    __shared__ uint32_t lds_a[PADDED_LDS];
    __shared__ uint32_t lds_b[PADDED_LDS];

    const uint32_t tid = threadIdx.x;
    const uint32_t n = 1u << lg_n;
    const uint32_t block_start = blockIdx.x * LDS_SIZE;

    if (block_start >= n) return;

    // Load from global to LDS
    for (uint32_t i = tid; i < LDS_SIZE; i += blockDim.x) {
        uint32_t gidx = block_start + i;
        lds_a[LDS_PAD(i)] = (gidx < n) ? d_in[gidx] : 0;
    }
    __syncthreads();

    // Process LDS_STAGES butterfly stages
    uint32_t* src = lds_a;
    uint32_t* dst = lds_b;

    for (uint32_t s = 0; s < LDS_STAGES && (outer_stage + s) < lg_n; s++) {
        uint32_t stage = outer_stage + s;
        uint32_t half = 1u << s;
        uint32_t full = half << 1;

        for (uint32_t i = tid; i < (LDS_SIZE >> 1); i += blockDim.x) {
            uint32_t group = i / half;
            uint32_t pos = i % half;

            // Stockham: read from even/odd positions
            uint32_t src_even = group * full + pos;
            uint32_t src_odd = src_even + half;

            // Write to consecutive positions (auto-sort)
            uint32_t dst_top = group * half + pos;
            uint32_t dst_bot = dst_top + (LDS_SIZE >> 1);

            uint32_t a = src[LDS_PAD(src_even)];
            uint32_t b = src[LDS_PAD(src_odd)];

            // Twiddle factor for this position at this stage
            // w = root^(pos * (n / full)) where root is primitive n-th root of unity
            uint32_t twiddle_idx = pos * (n >> (stage + 1));
            uint32_t w = root_table[twiddle_idx & ((n >> 1) - 1)];

            kb_butterfly(a, b, w);

            dst[LDS_PAD(dst_top)] = a;
            dst[LDS_PAD(dst_bot)] = b;
        }
        __syncthreads();

        // Swap ping-pong
        uint32_t* tmp = src;
        src = dst;
        dst = tmp;
    }

    // Write back to global memory
    for (uint32_t i = tid; i < LDS_SIZE; i += blockDim.x) {
        uint32_t gidx = block_start + i;
        if (gidx < n) d_out[gidx] = src[LDS_PAD(i)];
    }
}

// ================================================================
// Global butterfly kernel for stages that span multiple blocks
// Each stage reads all N elements and writes all N elements
// Optimized for coalesced memory access on RDNA
// ================================================================
__global__ __launch_bounds__(256)
void rdna_global_butterfly_kernel(
    uint32_t* __restrict__ d_out,
    const uint32_t* __restrict__ d_in,
    const uint32_t* __restrict__ root_table,
    uint32_t lg_n,
    uint32_t stage
) {
    const uint32_t n = 1u << lg_n;
    const uint32_t half = 1u << stage;
    const uint32_t full = half << 1;
    const uint32_t stride = blockDim.x * gridDim.x;

    for (uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
         i < (n >> 1);
         i += stride) {

        uint32_t group = i / half;
        uint32_t pos = i % half;
        uint32_t idx_a = group * full + pos;
        uint32_t idx_b = idx_a + half;

        uint32_t a = d_in[idx_a];
        uint32_t b = d_in[idx_b];

        uint32_t twiddle_idx = pos * (n >> (stage + 1));
        uint32_t w = root_table[twiddle_idx & ((n >> 1) - 1)];

        kb_butterfly(a, b, w);

        d_out[idx_a] = a;
        d_out[idx_b] = b;
    }
}

// ================================================================
// Complete Stockham NTT driver
// Decomposes lg_n stages into:
//   - First LDS_STAGES stages: processed entirely in LDS
//   - Remaining stages: processed with global memory butterflies
// ================================================================
class RdnaNTT {
public:
    // Root table: precomputed powers of primitive root in Montgomery form
    // root_table[k] = g^k mod p in Montgomery form
    // where g is a primitive 2^lg_n-th root of unity
    static void forward(
        hipStream_t stream,
        uint32_t* d_out,
        const uint32_t* d_in,
        const uint32_t* root_table,
        uint32_t lg_n
    ) {
        uint32_t n = 1u << lg_n;

        if (lg_n <= 10) {
            // Small NTT: process entirely in LDS
            uint32_t blocks = 1;
            rdna_stockham_lds_kernel<10><<<blocks, 512, 0, stream>>>(
                d_out, d_in, root_table, lg_n, 0);
        } else {
            // Large NTT: first 10 stages in LDS, rest global
            uint32_t lds_blocks = (n + 1023) / 1024;
            rdna_stockham_lds_kernel<10><<<lds_blocks, 512, 0, stream>>>(
                d_out, d_in, root_table, lg_n, 0);

            // Remaining stages as global butterflies
            uint32_t grid = std::min((n/2 + 255) / 256, 48u * 8);
            for (uint32_t s = 10; s < lg_n; s++) {
                rdna_global_butterfly_kernel<<<grid, 256, 0, stream>>>(
                    d_out, d_out, root_table, lg_n, s);
            }
        }
    }
};
