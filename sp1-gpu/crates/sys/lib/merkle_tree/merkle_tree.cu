#include <stdio.h>
#include "poseidon2/poseidon2_kb31_16.cuh"
#include "poseidon2/poseidon2.cuh"
#include "poseidon2/poseidon2_bn254_3.cuh"

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