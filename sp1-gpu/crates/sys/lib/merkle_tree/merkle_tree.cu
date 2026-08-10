#include <stdio.h>
#include <cstdint>
#include "poseidon2/poseidon2_kb31_16.cuh"
#include "poseidon2/poseidon2.cuh"
#include "poseidon2/poseidon2_bn254_3.cuh"
#include "scan/scan.cuh"

template <typename Hasher_t, typename HashParams, typename HasherState_t>
__global__ void leafHash(
    Hasher_t hasher,
    kb31_t* input,
    typename HashParams::F_t (*digests)[HashParams::DIGEST_WIDTH],
    size_t widths,
    size_t tree_height) {
    HasherState_t state;

    size_t matrixHeight = 1 << tree_height;
    for (size_t idx = (blockIdx.x * blockDim.x) + threadIdx.x; idx < matrixHeight;
         idx += blockDim.x * gridDim.x) {
        state.absorbRow(hasher, input, idx, widths, matrixHeight);
        size_t digestIdx = idx + (matrixHeight - 1);
        state.finalize(hasher, digests[digestIdx]);
    }
}

// Leaf hashing that absorbs a whole RATE block at a time. Consuming RATE elements at once makes 
// every state index compile-time constant and lets the RATE loads issue together.
template <typename Hasher_t, typename HashParams>
__global__ void leafHashPacked(
    Hasher_t hasher,
    const typename HashParams::F_t* __restrict__ input,
    typename HashParams::F_t (*digests)[HashParams::DIGEST_WIDTH],
    size_t widths,
    size_t tree_height) {
    using F_t = typename HashParams::F_t;
    using FDW_t = poseidon2::FDW_t<HashParams>;
    constexpr int WIDTH = HashParams::WIDTH;
    constexpr int RATE = HashParams::RATE;

    const size_t matrixHeight = (size_t)1 << tree_height;
    for (size_t idx = (blockIdx.x * blockDim.x) + threadIdx.x; idx < matrixHeight;
         idx += blockDim.x * gridDim.x) {
        __align__(16) F_t state[WIDTH];
#pragma unroll
        for (int i = 0; i < WIDTH; i++) {
            state[i].set_to_zero();
        }

        const F_t* column = input + idx;
        size_t j = 0;
        for (; j + RATE <= widths; j += RATE) {
#pragma unroll
            for (int k = 0; k < RATE; k++) {
                state[k] = column[(j + k) * matrixHeight];
            }
            hasher.permute(state, state);
        }
        const size_t rem = widths - j;
        if (rem != 0) {
#pragma unroll
            for (int k = 0; k < RATE; k++) {
                if ((size_t)k < rem) {
                    state[k] = column[(j + k) * matrixHeight];
                }
            }
            hasher.permute(state, state);
        }

        *reinterpret_cast<FDW_t*>(digests[idx + (matrixHeight - 1)]) =
            *reinterpret_cast<FDW_t*>(state);
    }
}

extern "C" void* leaf_hash_merkle_tree_koala_bear_16_kernel() {
    return (void*)leafHashPacked<poseidon2::KoalaBearHasher, poseidon2_kb31_16::KoalaBear>;
}

extern "C" void* leaf_hash_merkle_tree_bn254_kernel() {
    return (void*)
        leafHash<poseidon2::Bn254Hasher, poseidon2_bn254_3::Bn254, poseidon2::Bn254HasherState>;
}

template <typename Hasher_t, typename HashParams, typename HasherState_t>
__global__ void compress(
    Hasher_t hasher,
    typename HashParams::F_t (*digests)[HashParams::DIGEST_WIDTH],
    size_t layer_height) {
    size_t layerLength = 1 << layer_height;
    for (int i = (blockIdx.x * blockDim.x) + threadIdx.x; i < layerLength;
         i += blockDim.x * gridDim.x) {
        size_t idx = i + (layerLength - 1);
        size_t leftIdx = (idx << 1) + 1;
        size_t rightIdx = leftIdx + 1;
        hasher.compress(digests[leftIdx], digests[rightIdx], digests[idx]);
    }
}

extern "C" void* compress_merkle_tree_koala_bear_16_kernel() {
    return (void*)compress<
        poseidon2::KoalaBearHasher,
        poseidon2_kb31_16::KoalaBear,
        poseidon2::KoalaBearHasherState>;
}

extern "C" void* compress_merkle_tree_bn254_kernel() {
    return (void*)
        compress<poseidon2::Bn254Hasher, poseidon2_bn254_3::Bn254, poseidon2::Bn254HasherState>;
}


// Walks the stored levels of a (possibly truncated) tree. For a truncated tree the caller
// shifts the leaf indices down to the stored leaf level (`index_shift`) and offsets the
// output past the recomputed bottom siblings (`path_offset`); `path_stride` stays full.
template <typename Hasher_t, typename HashParams, typename HasherState_t>
__global__ void computePaths(
    typename HashParams::F_t (*paths)[HashParams::DIGEST_WIDTH],
    size_t path_stride,
    size_t path_offset,
    size_t* indices,
    size_t index_shift,
    size_t numIndices,
    typename HashParams::F_t (*digests)[HashParams::DIGEST_WIDTH],
    size_t stored_height) {
    for (int i = (blockIdx.x * blockDim.x) + threadIdx.x; i < numIndices;
         i += blockDim.x * gridDim.x) {
        size_t idx = ((size_t)1 << stored_height) - 1 + (indices[i] >> index_shift);
        for (int k = 0; k < stored_height; k++) {
            size_t siblingIdx = ((idx - 1) ^ 1) + 1;
            size_t parentIdx = (idx - 1) >> 1;
            typename HashParams::F_t* digest = digests[siblingIdx];
            typename HashParams::F_t* path_digest = paths[i * path_stride + path_offset + k];
#pragma unroll
            for (int j = 0; j < HashParams::DIGEST_WIDTH; j++) {
                path_digest[j] = digest[j];
            }
            idx = parentIdx;
        }
    }
}

// Recomputes the bottom `bottom_levels` path siblings of each query from the leaf data.
// One block per query: the block re-hashes the query's 2^bottom_levels-leaf subtree into
// shared memory and reduces it level by level.
template <typename Hasher_t, typename HashParams, typename HasherState_t>
__global__ void recomputeBottomPaths(
    Hasher_t hasher,
    kb31_t* input,
    typename HashParams::F_t (*paths)[HashParams::DIGEST_WIDTH],
    size_t* indices,
    size_t numIndices,
    size_t widths,
    size_t tree_height,
    size_t bottom_levels) {
    using FDW_t = poseidon2::FDW_t<HashParams>;
    static_assert(
        sizeof(FDW_t) == HashParams::DIGEST_WIDTH * sizeof(typename HashParams::F_t),
        "digest slots must be tightly packed");
    extern __shared__ unsigned char smemRaw[];
    FDW_t* nodes = reinterpret_cast<FDW_t*>(smemRaw);

    size_t matrixHeight = (size_t)1 << tree_height;
    size_t subtreeLeaves = (size_t)1 << bottom_levels;

    for (size_t q = blockIdx.x; q < numIndices; q += gridDim.x) {
        size_t leafIdx = indices[q];
        size_t base = (leafIdx >> bottom_levels) << bottom_levels;
        size_t local = leafIdx - base;

        for (size_t t = threadIdx.x; t < subtreeLeaves; t += blockDim.x) {
            HasherState_t state;
            state.absorbRow(hasher, input, base + t, widths, matrixHeight);
            state.finalize(hasher, nodes[t].v);
        }
        __syncthreads();

        size_t levelBase = 0;
        size_t levelLen = subtreeLeaves;
        for (size_t k = 0; k < bottom_levels; k++) {
            if (threadIdx.x == 0) {
                FDW_t* sibling = &nodes[levelBase + ((local >> k) ^ 1)];
                typename HashParams::F_t* path_digest = paths[q * tree_height + k];
#pragma unroll
                for (int j = 0; j < HashParams::DIGEST_WIDTH; j++) {
                    path_digest[j] = sibling->v[j];
                }
            }
            if (k + 1 == bottom_levels) {
                break;
            }
            size_t nextBase = levelBase + levelLen;
            for (size_t t = threadIdx.x; t < (levelLen >> 1); t += blockDim.x) {
                hasher.compress(
                    nodes[levelBase + 2 * t].v,
                    nodes[levelBase + 2 * t + 1].v,
                    nodes[nextBase + t].v);
            }
            __syncthreads();
            levelBase = nextBase;
            levelLen >>= 1;
        }
        // The next query reuses the shared slots; make sure this query's reads are done.
        __syncthreads();
    }
}


extern "C" void* compute_paths_merkle_tree_koala_bear_16_kernel() {
    return (void*)computePaths<
        poseidon2::KoalaBearHasher,
        poseidon2_kb31_16::KoalaBear,
        poseidon2::KoalaBearHasherState>;
}

extern "C" void* compute_paths_merkle_tree_bn254_kernel() {
    return (void*)
        computePaths<poseidon2::Bn254Hasher, poseidon2_bn254_3::Bn254, poseidon2::Bn254HasherState>;
}

extern "C" void* recompute_bottom_paths_merkle_tree_koala_bear_16_kernel() {
    return (void*)recomputeBottomPaths<
        poseidon2::KoalaBearHasher,
        poseidon2_kb31_16::KoalaBear,
        poseidon2::KoalaBearHasherState>;
}

extern "C" void* recompute_bottom_paths_merkle_tree_bn254_kernel() {
    return (void*)recomputeBottomPaths<
        poseidon2::Bn254Hasher,
        poseidon2_bn254_3::Bn254,
        poseidon2::Bn254HasherState>;
}


template <typename Hasher_t, typename HashParams, typename HasherState_t>
__global__ void computeOpenings(
    kb31_t** __restrict__ inputs,
    kb31_t* __restrict__ outputs,
    size_t* indices,
    size_t numIndices,
    size_t numInputs,
    size_t* batchSizes,
    size_t* batchOffsets,
    size_t matrixHeight,
    size_t numOpeningValues) {
    for (size_t batchIdx = (blockIdx.z * blockDim.z) + threadIdx.z; batchIdx < numInputs;
         batchIdx += blockDim.z * gridDim.z) {
        kb31_t* in = inputs[batchIdx];
        size_t offset = batchOffsets[batchIdx];
        size_t batchSize = batchSizes[batchIdx];
        for (size_t i = (blockIdx.x * blockDim.x) + threadIdx.x; i < numIndices;
             i += blockDim.x * gridDim.x) {
            size_t rowIdx = indices[i];
            for (size_t j = (blockIdx.y * blockDim.y) + threadIdx.y; j < batchSize;
                 j += blockDim.y * gridDim.y) {
                outputs[i * numOpeningValues + j + offset] = in[j * matrixHeight + rowIdx];
            }
        }
    }
}

extern "C" void* compute_openings_merkle_tree_koala_bear_16_kernel() {
    return (void*)computeOpenings<
        poseidon2::KoalaBearHasher,
        poseidon2_kb31_16::KoalaBear,
        poseidon2::KoalaBearHasherState>;
}

extern "C" void* compute_openings_merkle_tree_bn254_kernel() {
    return (void*)computeOpenings<
        poseidon2::Bn254Hasher,
        poseidon2_bn254_3::Bn254,
        poseidon2::Bn254HasherState>;
}

// Hash N independent contiguous pages of page_size field elements each.
// Each thread hashes one page using the Poseidon2 sponge.
template <typename Hasher_t, typename HashParams>
__global__ void hashPages(
    typename HashParams::F_t* input,
    typename HashParams::F_t (*digests)[HashParams::DIGEST_WIDTH],
    size_t page_size,
    size_t num_pages) {
    for (size_t idx = blockIdx.x * blockDim.x + threadIdx.x; idx < num_pages;
         idx += blockDim.x * gridDim.x) {
        Hasher_t::hash(&input[idx * page_size], page_size, digests[idx]);
    }
}

extern "C" void* hash_pages_koala_bear_16_kernel() {
    return (void*)hashPages<poseidon2::KoalaBearHasher, poseidon2_kb31_16::KoalaBear>;
}

// ===========================================================================
// Structure built on the GPU. Each level is stored as a sorted (idx, val)
// pair of arrays. A level is built from the level below by (1) flagging the
// "leaders" (first child of each distinct parent), (2) scanning the flags to
// get output positions, (3) a segmented compress where each leader reads its
// 1-2 *adjacent* children — no precomputed child pointers, no host work.
// ===========================================================================

// Histogram of msb(idx[i] ^ idx[i-1]) over adjacent (sorted, distinct) indices, into
// `hist[0..=H]`. From this the per-level node counts follow without walking levels:
//   count[h] = 1 + sum_{b >= H-h} hist[b]   (count[H] = n).
// Block-shared accumulation then one atomic per nonempty bin keeps global contention low.
__global__ void countHistogram(const uint32_t* __restrict__ idx, uint32_t n, uint32_t* __restrict__ hist) {
    __shared__ uint32_t sh[32];
    for (int t = threadIdx.x; t < 32; t += blockDim.x) {
        sh[t] = 0;
    }
    __syncthreads();
    for (uint32_t i = blockIdx.x * blockDim.x + threadIdx.x; i < n;
         i += blockDim.x * gridDim.x) {
        if (i == 0) {
            continue;
        }
        uint32_t d = idx[i] ^ idx[i - 1];
        uint32_t b = 31u - __clz(d); // d != 0: indices are sorted & distinct
        atomicAdd(&sh[b], 1u);
    }
    __syncthreads();
    for (int t = threadIdx.x; t < 32; t += blockDim.x) {
        if (sh[t] != 0) {
            atomicAdd(&hist[t], sh[t]);
        }
    }
}

extern "C" void* count_histogram_merkle_tree_kernel() {
    return (void*)countHistogram;
}

// flags[j] = 1 iff child j is the first child of its parent (idx[j]>>1 changes).
__global__ void prevLeaderFlags(
    const uint32_t* __restrict__ cidx, uint32_t n, uint32_t* __restrict__ flags) {
    for (uint32_t j = blockIdx.x * blockDim.x + threadIdx.x; j < n;
         j += blockDim.x * gridDim.x) {
        flags[j] = (j == 0 || (cidx[j] >> 1) != (cidx[j - 1] >> 1)) ? 1u : 0u;
    }
}

// Reset the inter-block scratch the chained scan needs (run before each scan).
__global__ void scanReset(
    uint32_t* __restrict__ scan_values,
    uint32_t* __restrict__ block_counter,
    uint32_t* __restrict__ block_flags,
    uint32_t num_blocks) {
    for (uint32_t i = blockIdx.x * blockDim.x + threadIdx.x; i < num_blocks + 1;
         i += blockDim.x * gridDim.x) {
        block_flags[i] = (i == 0) ? 1u : 0u;
        scan_values[i] = 0u;
    }
    if (blockIdx.x == 0 && threadIdx.x == 0) {
        *block_counter = 0u;
    }
}

// Compact the leaders: `leader_pos[incl[j]-1] = j` for each leader (`flags[j] != 0`).
// `incl` is the inclusive scan of `flags`, so a leader at `j` lands at its scanned rank.
// This is a cheap single-word scatter; the expensive compress below is then dense.
__global__ void prevScatterLeaders(
    const uint32_t* __restrict__ flags,
    const uint32_t* __restrict__ incl,
    uint32_t n,
    uint32_t* __restrict__ leader_pos) {
    for (uint32_t j = blockIdx.x * blockDim.x + threadIdx.x; j < n;
         j += blockDim.x * gridDim.x) {
        if (flags[j] != 0) {
            leader_pos[incl[j] - 1] = j;
        }
    }
}

// Dense compress: one thread per parent, `leader_pos[t]` being the child index `j` of the
// t-th parent, so every thread runs the Poseidon2 compress (no control divergence over it).
// Children are adjacent: an even child is the left and its right sibling is the next entry
// iff it shares the parent; an odd child is the right (left absent).
__global__ void prevCompressDense(
    const uint32_t* __restrict__ leader_pos,
    uint32_t num_leaders,
    const uint32_t* __restrict__ cidx,
    const kb31_t (*cval)[8],
    uint32_t n,
    const kb31_t* __restrict__ default_child,
    uint32_t* __restrict__ pidx,
    kb31_t (*pval)[8]) {
    for (uint32_t t = blockIdx.x * blockDim.x + threadIdx.x; t < num_leaders;
         t += blockDim.x * gridDim.x) {
        uint32_t j = leader_pos[t];
        uint32_t ci = cidx[j];
        kb31_t left[8], right[8], res[8];
        if ((ci & 1u) == 0) {
            // Left child present; right sibling is the next entry iff same parent.
            bool has_right = (j + 1 < n) && (cidx[j + 1] == ci + 1);
#pragma unroll
            for (int k = 0; k < 8; k++) {
                left[k] = cval[j][k];
                right[k] = has_right ? cval[j + 1][k] : default_child[k];
            }
        } else {
            // Only the right child is present.
#pragma unroll
            for (int k = 0; k < 8; k++) {
                left[k] = default_child[k];
                right[k] = cval[j][k];
            }
        }
        poseidon2::KoalaBearHasher::compress(left, right, res);
        pidx[t] = ci >> 1;
#pragma unroll
        for (int k = 0; k < 8; k++) {
            pval[t][k] = res[k];
        }
    }
}

extern "C" void* prev_leader_flags_merkle_tree_kernel() {
    return (void*)prevLeaderFlags;
}
extern "C" void* scan_reset_merkle_tree_kernel() {
    return (void*)scanReset;
}
extern "C" void* scan_u32_merkle_tree_kernel() {
    return (void*)scan_large::Scan<uint32_t>;
}
extern "C" void* prev_scatter_leaders_merkle_tree_kernel() {
    return (void*)prevScatterLeaders;
}
extern "C" void* prev_compress_dense_merkle_tree_kernel() {
    return (void*)prevCompressDense;
}

// ===========================================================================
// Stage C: current-tree build + tagged emit over the (small) active set.
// Children/frontier values are resolved by lower_bound into the resident sorted
// arrays — never a host search.
// ===========================================================================

// Index of `key` in sorted `arr[0..n)`, or -1 if absent.
__device__ __forceinline__ int lbFind(const uint32_t* arr, uint32_t n, uint32_t key) {
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = (lo + hi) >> 1;
        if (arr[mid] < key) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return (lo < n && arr[lo] == key) ? (int)lo : -1;
}

// Resolve child `c`: its current value if active, else its prev value, else the default.
__device__ __forceinline__ void resolveChild(
    uint32_t c,
    const uint32_t* act_idx, uint32_t n_act, const kb31_t (*act_val)[8],
    const uint32_t* prev_idx, uint32_t n_prev, const kb31_t (*prev_val)[8],
    const kb31_t* def, kb31_t out[8]) {
    int pa = lbFind(act_idx, n_act, c);
    if (pa >= 0) {
#pragma unroll
        for (int k = 0; k < 8; k++) out[k] = act_val[pa][k];
        return;
    }
    int pp = lbFind(prev_idx, n_prev, c);
    const kb31_t* src = (pp >= 0) ? prev_val[pp] : def;
#pragma unroll
    for (int k = 0; k < 8; k++) out[k] = src[k];
}

// Current value of each active node at level h: compress over its two children, where 
// each child is taken from the active (current) array if present, else the resident 
// prev array, else the default.
__global__ void curCompress(
    const uint32_t* __restrict__ node_idx, uint32_t n_a,
    const uint32_t* __restrict__ act_child_idx, uint32_t n_ac, const kb31_t (*act_child_val)[8],
    const uint32_t* __restrict__ prev_child_idx, uint32_t n_pc, const kb31_t (*prev_child_val)[8],
    const kb31_t* __restrict__ default_child,
    kb31_t (*out_val)[8]) {
    for (uint32_t p = blockIdx.x * blockDim.x + threadIdx.x; p < n_a;
         p += blockDim.x * gridDim.x) {
        uint32_t idx = node_idx[p];
        kb31_t left[8], right[8], res[8];
        resolveChild(2 * idx, act_child_idx, n_ac, act_child_val, prev_child_idx, n_pc,
                     prev_child_val, default_child, left);
        resolveChild(2 * idx + 1, act_child_idx, n_ac, act_child_val, prev_child_idx, n_pc,
                     prev_child_val, default_child, right);
        poseidon2::KoalaBearHasher::compress(left, right, res);
#pragma unroll
        for (int k = 0; k < 8; k++) out_val[p][k] = res[k];
    }
}

__device__ __forceinline__ uint8_t nodeTagCode(bool init, uint32_t h) {
    if (init) return (h == 0) ? 0u : 1u;   // InitRoot : InitInternal
    return (h == 0) ? 3u : 4u;             // FinalRoot : FinalInternal
}
__device__ __forceinline__ uint8_t childTagCode(bool active, bool init, uint32_t child_lvl, uint32_t H) {
    if (!active) return 6u;                          // Shared
    if (init) return (child_lvl == H) ? 2u : 1u;     // InitLeave : InitInternal
    return (child_lvl == H) ? 5u : 4u;               // FinalLeave : FinalInternal
}

// Emit the two trace rows (prev mult=+1, current mult=-1) for each active internal
// node at level h. Row pair p writes rows (row_base + 2p) and (row_base + 2p + 1).
__global__ void emitRows(
    const uint32_t* __restrict__ node_idx, uint32_t n_a, uint32_t h, uint32_t H,
    // self at level h
    const uint32_t* __restrict__ prev_self_idx, uint32_t n_ps, const kb31_t (*prev_self_val)[8],
    const kb31_t* __restrict__ default_self, const kb31_t (*cur_self_val)[8],
    // children at level h+1
    const uint32_t* __restrict__ act_child_idx, uint32_t n_ac, const kb31_t (*act_child_val)[8],
    const uint32_t* __restrict__ prev_child_idx, uint32_t n_pc, const kb31_t (*prev_child_val)[8],
    const kb31_t* __restrict__ default_child,
    // outputs
    uint32_t row_base, kb31_t (*out_tlr)[8], uint32_t* out_height, uint32_t* out_idx,
    uint8_t* out_tag1, uint8_t* out_tag2, uint8_t* out_tag3, int8_t* out_mult) {
    for (uint32_t p = blockIdx.x * blockDim.x + threadIdx.x; p < n_a;
         p += blockDim.x * gridDim.x) {
        uint32_t idx = node_idx[p];
        uint32_t c0 = 2 * idx, c1 = 2 * idx + 1;

        // self prev value (lower_bound into prev level h)
        kb31_t prevT[8];
        {
            int ps = lbFind(prev_self_idx, n_ps, idx);
            const kb31_t* s = (ps >= 0) ? prev_self_val[ps] : default_self;
#pragma unroll
            for (int k = 0; k < 8; k++) prevT[k] = s[k];
        }
        // children prev values + active flags
        kb31_t prevL[8], prevR[8];
        resolveChild(c0, act_child_idx, 0, act_child_val, prev_child_idx, n_pc, prev_child_val,
                     default_child, prevL); // n_ac=0 forces prev/default path
        resolveChild(c1, act_child_idx, 0, act_child_val, prev_child_idx, n_pc, prev_child_val,
                     default_child, prevR);
        int a0 = lbFind(act_child_idx, n_ac, c0);
        int a1 = lbFind(act_child_idx, n_ac, c1);

        // current values: active child -> cur array, else same as prev
        kb31_t curL[8], curR[8];
        if (a0 >= 0) {
#pragma unroll
            for (int k = 0; k < 8; k++) curL[k] = act_child_val[a0][k];
        } else {
#pragma unroll
            for (int k = 0; k < 8; k++) curL[k] = prevL[k];
        }
        if (a1 >= 0) {
#pragma unroll
            for (int k = 0; k < 8; k++) curR[k] = act_child_val[a1][k];
        } else {
#pragma unroll
            for (int k = 0; k < 8; k++) curR[k] = prevR[k];
        }

        uint32_t prow = row_base + 2 * p;
        uint32_t crow = prow + 1;

        // prev row (mult = +1)
#pragma unroll
        for (int k = 0; k < 8; k++) {
            out_tlr[3 * prow + 0][k] = prevT[k];
            out_tlr[3 * prow + 1][k] = prevL[k];
            out_tlr[3 * prow + 2][k] = prevR[k];
        }
        out_height[prow] = h;
        out_idx[prow] = idx;
        out_tag1[prow] = nodeTagCode(true, h);
        out_tag2[prow] = childTagCode(a0 >= 0, true, h + 1, H);
        out_tag3[prow] = childTagCode(a1 >= 0, true, h + 1, H);
        out_mult[prow] = 1;

        // current row (mult = -1)
#pragma unroll
        for (int k = 0; k < 8; k++) {
            out_tlr[3 * crow + 0][k] = cur_self_val[p][k];
            out_tlr[3 * crow + 1][k] = curL[k];
            out_tlr[3 * crow + 2][k] = curR[k];
        }
        out_height[crow] = h;
        out_idx[crow] = idx;
        out_tag1[crow] = nodeTagCode(false, h);
        out_tag2[crow] = childTagCode(a0 >= 0, false, h + 1, H);
        out_tag3[crow] = childTagCode(a1 >= 0, false, h + 1, H);
        out_mult[crow] = -1;
    }
}

extern "C" void* cur_compress_merkle_tree_kernel() {
    return (void*)curCompress;
}
extern "C" void* emit_rows_merkle_tree_kernel() {
    return (void*)emitRows;
}