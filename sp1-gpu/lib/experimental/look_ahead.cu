#include "experimental/look_ahead.cuh"

#include "config.cuh"

#include <cuda/pipeline>
#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>
#include <cstdint>

namespace cg = cooperative_groups;

constexpr size_t MAX_RESTRICT_SIZE = 16;

__constant__ ext_t restrictEq[MAX_RESTRICT_SIZE] = {
    ext_t(1, 1, 1, 1),
    ext_t(2, 2, 2, 2),
    ext_t(3, 3, 3, 3),
    ext_t(4, 4, 4, 4),
    ext_t(5, 5, 5, 5),
    ext_t(6, 6, 6, 6),
    ext_t(7, 7, 7, 7),
    ext_t(8, 8, 8, 8),
    ext_t(9, 9, 9, 9),
    ext_t(10, 10, 10, 10),
    ext_t(11, 11, 11, 11),
    ext_t(12, 12, 12, 12),
    ext_t(13, 13, 13, 13),
    ext_t(14, 14, 14, 14),
    ext_t(15, 15, 15, 15),
    ext_t(16, 16, 16, 16),
};

extern "C" rustCudaError_t
populate_restrict_eq_host(const void* src, size_t len, cudaStream_t stream) {
    CUDA_OK(cudaMemcpyToSymbolAsync(
        (const void*)restrictEq,
        src,
        len * sizeof(ext_t),
        0,
        cudaMemcpyHostToDevice,
        stream));
    return CUDA_SUCCESS_CSL;
}

extern "C" rustCudaError_t
populate_restrict_eq_device(const void* src, size_t len, cudaStream_t stream) {
    CUDA_OK(cudaMemcpyToSymbolAsync(
        (const void*)restrictEq,
        src,
        len * sizeof(ext_t),
        0,
        cudaMemcpyDeviceToDevice,
        stream));
    return CUDA_SUCCESS_CSL;
}

template <size_t POINTS, size_t WIDTH>
static __constant__ felt_t evalEq[POINTS][WIDTH];

template <>
__constant__ felt_t evalEq<1, 1>[1][1] = {
    felt_t(1),
};

template <>
inline __constant__ felt_t evalEq<2, 2>[2][2] = {
    felt_t(1),
    felt_t(0),
    felt_t(1),
    felt_t(1),
};

template <>
inline __constant__ felt_t evalEq<3, 2>[3][2] = {
    felt_t(0),
    felt_t(1),
    felt_t(1),
    felt_t(0),
    felt_t(1),
    felt_t(1),
};

template <>
inline __constant__ felt_t evalEq<8, 4>[8][4] = {
    felt_t(0), felt_t(1), felt_t(2), felt_t(3), felt_t(1), felt_t(0), felt_t(3), felt_t(2),
    felt_t(2), felt_t(3), felt_t(0), felt_t(1), felt_t(3), felt_t(2), felt_t(1), felt_t(0),
    felt_t(4), felt_t(5), felt_t(6), felt_t(7), felt_t(5), felt_t(4), felt_t(7), felt_t(6),
    felt_t(6), felt_t(7), felt_t(4), felt_t(5), felt_t(7), felt_t(6), felt_t(5), felt_t(4),
};


template <
    size_t FIX_GROUP = 2,
    size_t FIX_TILE = 32,
    size_t SUM_GROUP = 2,
    size_t NUM_POINTS = 2,
    bool STORE_RESTRICTED = true>
__global__ void roundKernel(
    ext_t* __restrict__ result,
    const ext_t* __restrict__ p,
    const ext_t* __restrict__ q,
    ext_t* __restrict__ p_restricted,
    ext_t* __restrict__ q_restricted,
    size_t block_height,
    size_t height) {
    auto block = cg::this_thread_block();
    auto warp = cg::tiled_partition<32>(block);

    auto fix_last_tile = cg::tiled_partition<FIX_GROUP>(warp);

    constexpr size_t NUM_FIX_GROUPS = 32 / FIX_GROUP;
    constexpr size_t TILES_PER_WARP = FIX_TILE / NUM_FIX_GROUPS;
    constexpr size_t WARP_SPAN = TILES_PER_WARP * 32;

    const size_t block_tile = blockDim.x * TILES_PER_WARP;

    extern __shared__ __align__(16) uint8_t smem[];
    // Assign shared memory pointers for `p` and `q`
    ext_t* p_smem = reinterpret_cast<ext_t*>(smem);
    ext_t* q_smem =
        reinterpret_cast<ext_t*>(smem + warp.meta_group_size() * FIX_TILE * sizeof(ext_t));
    ext_t* result_smem =
        reinterpret_cast<ext_t*>(smem + warp.meta_group_size() * FIX_TILE * 2 * sizeof(ext_t));


    auto sum_as_poly_tile = cg::tiled_partition<SUM_GROUP>(warp);

    for (int point = 0; point < NUM_POINTS; ++point) {
        // result_smem[warp.meta_group_size() * point + warp.meta_group_rank()] = ext_t::zero();
        ext_t::store(
            result_smem,
            warp.meta_group_size() * point + warp.meta_group_rank(),
            ext_t::zero());
    }

    // Iterate over block tiles -> warp tiles
    for (int b_idx = blockIdx.x * block_tile; b_idx < block_height;
         b_idx += gridDim.x * block_tile) {

// Stage 1: Fix last variable of `q` and `p` into shared memory and store the values in
// the global memory for the next round.
#pragma unroll
        for (int tile = 0; tile < TILES_PER_WARP; ++tile) {
            ext_t p_red;
            ext_t q_red;
            int idx = b_idx + WARP_SPAN * warp.meta_group_rank() + tile * 32 + warp.thread_rank();
            if (idx < height) {
                if constexpr (FIX_GROUP == 1) {
                    p_red = ext_t::load(p, idx);
                    q_red = ext_t::load(q, idx);
                } else {
                    p_red = ext_t::load(p, idx) * restrictEq[fix_last_tile.thread_rank()];
                    q_red = ext_t::load(q, idx) * restrictEq[fix_last_tile.thread_rank()];
                }
            } else {
                q_red = ext_t::zero();
                p_red = ext_t::zero();
            }
            p_red = cg::reduce(fix_last_tile, p_red, cg::plus<ext_t>());
            q_red = cg::reduce(fix_last_tile, q_red, cg::plus<ext_t>());

            if (fix_last_tile.thread_rank() == 0) {
                // Store the reduced values in global memory for caching the results of fixing the
                // last variable of the polynomials `q` and `p`.
                if constexpr (STORE_RESTRICTED) {
                    if (idx < height) {
                        const size_t store_idx = idx / FIX_GROUP;
                        ext_t::store(p_restricted, store_idx, p_red);
                        ext_t::store(q_restricted, store_idx, q_red);
                    }
                }

                // Store in shared memory for use in the next stage
                const int shared_mem_store_idx = warp.meta_group_rank() * FIX_TILE +
                                                 tile * fix_last_tile.meta_group_size() +
                                                 fix_last_tile.meta_group_rank();
                ext_t::store(p_smem, shared_mem_store_idx, p_red);
                ext_t::store(q_smem, shared_mem_store_idx, q_red);
            }
        }
        // Wait for all threads in the warp to finish the shared memory store operations
        warp.sync();


        // Stage 2: interpolate the polynomials `q` and `p` and compute the sumcheck expression

#pragma unroll
        for (int point = 0; point < NUM_POINTS; ++point) {
            ext_t p_local = ext_t::zero();
            ext_t q_local = ext_t::zero();
            // TODO: Correct loop bounds for different SUM_GROUP <> FIX_TILE configurations.
            for (int warp_tile = 0; warp_tile < (FIX_TILE / 32); ++warp_tile) {
                const int warp_base = warp.meta_group_rank() * FIX_TILE;
                const int base = warp_base + warp_tile * 32 + warp.thread_rank();

                ext_t p_interp =
                    p_smem[base] *
                    evalEq<NUM_POINTS, SUM_GROUP>[point][sum_as_poly_tile.thread_rank()];
                ext_t q_interp =
                    q_smem[base] *
                    evalEq<NUM_POINTS, SUM_GROUP>[point][sum_as_poly_tile.thread_rank()];

                p_interp = cg::reduce(sum_as_poly_tile, p_interp, cg::plus<ext_t>());
                q_interp = cg::reduce(sum_as_poly_tile, q_interp, cg::plus<ext_t>());

                // Get the reduction result to the warp offset warp_tile from leader warp of
                // the sum_as_poly_tile group, but only for that specifc thread, we don't want
                // the other q_local and p_local values to be affected.
                if (warp_tile == sum_as_poly_tile.thread_rank()) {
                    p_local = p_interp;
                    q_local = q_interp;
                }
            }
            ext_t hadamard = p_local * q_local;
            hadamard = cg::reduce(warp, hadamard, cg::plus<ext_t>());
            if (warp.thread_rank() == 0) {
                result_smem[warp.meta_group_size() * point + warp.meta_group_rank()] += hadamard;
            }
        }
        warp.sync();
    }
    // After all results were accumulated, perform a reduction between the warp tiles.
    block.sync();

    // Perform a reduction between the warp tiles.
    for (int stride = (block.size() / warp.size()) / 2; stride > 0; stride /= 2) {
        if (block.thread_rank() < stride) {
#pragma unroll
            for (size_t point = 0; point < NUM_POINTS; ++point) {
                const int base = warp.meta_group_size() * point + block.thread_rank();
                result_smem[base] += result_smem[base + stride];
            }
        }
        block.sync();
    }

// Store the results in the global memory
#pragma unroll
    for (int point = 0; point < NUM_POINTS; ++point) {
        ext_t res = result_smem[warp.meta_group_size() * point];
        ext_t::store(result, point * gridDim.x + blockIdx.x, res);
    }
}

extern "C" void* round_kernel_1_32_2_2_false() { return (void*)roundKernel<1, 32, 2, 2, false>; }


extern "C" void* round_kernel_2_32_2_2_true() { return (void*)roundKernel<2, 32, 2, 2, true>; }

extern "C" void* round_kernel_2_32_2_2_false() { return (void*)roundKernel<2, 32, 2, 2, false>; }

extern "C" void* round_kernel_4_32_2_2_true() { return (void*)roundKernel<4, 32, 2, 2, true>; }

extern "C" void* round_kernel_4_32_2_2_false() { return (void*)roundKernel<4, 32, 2, 2, false>; }

extern "C" void* round_kernel_8_32_2_2_true() { return (void*)roundKernel<8, 32, 2, 2, true>; }

extern "C" void* round_kernel_8_32_2_2_false() { return (void*)roundKernel<8, 32, 2, 2, false>; }

// FIX_TILE=64 variants
extern "C" void* round_kernel_1_64_2_2_false() { return (void*)roundKernel<1, 64, 2, 2, false>; }

extern "C" void* round_kernel_2_64_2_2_true() { return (void*)roundKernel<2, 64, 2, 2, true>; }

extern "C" void* round_kernel_2_64_2_2_false() { return (void*)roundKernel<2, 64, 2, 2, false>; }

extern "C" void* round_kernel_4_64_2_2_true() { return (void*)roundKernel<4, 64, 2, 2, true>; }

extern "C" void* round_kernel_4_64_2_2_false() { return (void*)roundKernel<4, 64, 2, 2, false>; }

extern "C" void* round_kernel_8_64_2_2_true() { return (void*)roundKernel<8, 64, 2, 2, true>; }

extern "C" void* round_kernel_8_64_2_2_false() { return (void*)roundKernel<8, 64, 2, 2, false>; }

// NUM_POINTS=3 variants with FIX_TILE=32
extern "C" void* round_kernel_1_32_2_3_false() { return (void*)roundKernel<1, 32, 2, 3, false>; }

extern "C" void* round_kernel_2_32_2_3_true() { return (void*)roundKernel<2, 32, 2, 3, true>; }

extern "C" void* round_kernel_2_32_2_3_false() { return (void*)roundKernel<2, 32, 2, 3, false>; }

extern "C" void* round_kernel_4_32_2_3_true() { return (void*)roundKernel<4, 32, 2, 3, true>; }

extern "C" void* round_kernel_4_32_2_3_false() { return (void*)roundKernel<4, 32, 2, 3, false>; }

extern "C" void* round_kernel_8_32_2_3_true() { return (void*)roundKernel<8, 32, 2, 3, true>; }

extern "C" void* round_kernel_8_32_2_3_false() { return (void*)roundKernel<8, 32, 2, 3, false>; }

// NUM_POINTS=3 variants with FIX_TILE=64
extern "C" void* round_kernel_1_64_2_3_false() { return (void*)roundKernel<1, 64, 2, 3, false>; }

extern "C" void* round_kernel_1_64_4_8_false() { return (void*)roundKernel<1, 64, 4, 8, false>; }

extern "C" void* round_kernel_2_64_2_3_true() { return (void*)roundKernel<2, 64, 2, 3, true>; }

extern "C" void* round_kernel_2_64_2_3_false() { return (void*)roundKernel<2, 64, 2, 3, false>; }

extern "C" void* round_kernel_4_64_2_3_true() { return (void*)roundKernel<4, 64, 2, 3, true>; }

extern "C" void* round_kernel_4_64_2_3_false() { return (void*)roundKernel<4, 64, 2, 3, false>; }

extern "C" void* round_kernel_4_64_4_8_true() { return (void*)roundKernel<4, 64, 4, 8, true>; }

extern "C" void* round_kernel_4_64_4_8_false() { return (void*)roundKernel<4, 64, 4, 8, false>; }

extern "C" void* round_kernel_8_64_2_3_true() { return (void*)roundKernel<8, 64, 2, 3, true>; }

extern "C" void* round_kernel_8_64_2_3_false() { return (void*)roundKernel<8, 64, 2, 3, false>; }


extern "C" void* round_kernel_1_128_4_8_false() { return (void*)roundKernel<1, 128, 4, 8, false>; }