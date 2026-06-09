// Device-side fold-metadata derivation for JaggedMle. See
// `fold_metadata.cuh` for the design and contract.
//
// Implementation = a multi-block decoupled-lookback inclusive scan with the
// fold transform fused into the load step and the exclusive-prefix shift
// fused into the write step. One launch handles any n_columns; supports
// regime-2 scale (millions of columns).
//
// Mirrors the pattern in `slop/.../scan.cuh::scan_large::Scan<T>`: each
// block atomically claims a sequential block_id, runs a local Brent-Kung
// scan in shared memory, then waits on the previous block's published
// prefix sum before adding it to its own results and publishing its own
// updated tail. The host pre-zeroes `block_counter` and `flags[0] = 1,
// flags[1..n_blocks+1] = 0` so the first block can proceed without
// waiting.

#include "jagged_assist/fold_metadata.cuh"
#include <cstdint>

namespace {

// SECTION_SIZE matches `scan_large::SECTION_SIZE` — each block scans 512
// elements with 256 threads (2 elements per thread). Block size is half the
// section so we can fit two values per thread plus the scan scratch.
constexpr uint32_t SECTION_SIZE = 512;
constexpr uint32_t BLOCK_DIM = SECTION_SIZE / 2;

// Apply `h.div_ceil(4) * 2` element-wise. Pure inline so the compiler folds
// it into the load.
__device__ __forceinline__ uint32_t fold_transform(uint32_t h) {
    return ((h + 3u) / 4u) * 2u;
}

__global__ void jaggedFoldMetadata(
    const uint32_t* __restrict__ column_heights,
    uint32_t n_columns,
    uint32_t* __restrict__ new_column_heights,
    uint32_t* __restrict__ new_start_indices,
    uint32_t* __restrict__ block_counter,
    uint32_t* __restrict__ flags,
    uint32_t* __restrict__ scan_values
) {
    // Claim a sequential block_id so blocks process the array left-to-right
    // (the decoupled-lookback chain needs strict ordering, the launch order
    // alone doesn't give us that).
    __shared__ uint32_t bid_s;
    if (threadIdx.x == 0) {
        bid_s = atomicAdd(block_counter, 1u);
    }
    __syncthreads();
    const uint32_t bid = bid_s;

    // Local block segment covers [bid*SECTION_SIZE, (bid+1)*SECTION_SIZE).
    const uint32_t tid = threadIdx.x;
    const uint32_t base = bid * SECTION_SIZE;
    const uint32_t i0 = base + tid;
    const uint32_t i1 = base + tid + BLOCK_DIM;

    // Phase 1 — load + transform (zero-pad out-of-range slots). The
    // transformed values are the inputs to the scan AND the output of
    // `new_column_heights`.
    __shared__ uint32_t aux[SECTION_SIZE];
    uint32_t h0 = (i0 < n_columns) ? fold_transform(column_heights[i0]) : 0u;
    uint32_t h1 = (i1 < n_columns) ? fold_transform(column_heights[i1]) : 0u;
    if (i0 < n_columns) {
        new_column_heights[i0] = h0;
    }
    if (i1 < n_columns) {
        new_column_heights[i1] = h1;
    }
    aux[tid] = h0;
    aux[tid + BLOCK_DIM] = h1;

    // Phase 2 — Brent-Kung inclusive scan in shared memory.
    for (uint32_t stride = 1; stride <= BLOCK_DIM; stride *= 2) {
        __syncthreads();
        uint32_t idx = (tid + 1) * stride * 2 - 1;
        if (idx < SECTION_SIZE) {
            aux[idx] += aux[idx - stride];
        }
    }
    for (uint32_t stride = BLOCK_DIM / 2; stride > 0; stride /= 2) {
        __syncthreads();
        uint32_t idx = (tid + 1) * stride * 2 - 1;
        if (idx + stride < SECTION_SIZE) {
            aux[idx + stride] += aux[idx];
        }
    }
    __syncthreads();

    // Phase 3 — decoupled lookback. Thread 0 spins on `flags[bid]` waiting
    // for the previous block to publish its prefix sum. Once available,
    // read it, propagate our own updated tail, and let the next block
    // proceed.
    __shared__ uint32_t previous_sum;
    if (tid == 0) {
        while (atomicAdd(&flags[bid], 0u) == 0u) {
        }
        previous_sum = scan_values[bid];
        scan_values[bid + 1u] = aux[SECTION_SIZE - 1u] + previous_sum;
        __threadfence();
        atomicAdd(&flags[bid + 1u], 1u);
    }
    __syncthreads();

    // Phase 4 — write exclusive prefix sum. inclusive_at(i) = prev_sum +
    // aux[i]; new_start_indices[i+1] = inclusive_at(i); new_start_indices[0]
    // = 0 (thread 0 of block 0 only).
    if (bid == 0u && tid == 0u) {
        new_start_indices[0] = 0u;
    }
    if (i0 < n_columns) {
        new_start_indices[i0 + 1u] = aux[tid] + previous_sum;
    }
    if (i1 < n_columns) {
        new_start_indices[i1 + 1u] = aux[tid + BLOCK_DIM] + previous_sum;
    }
}

}  // namespace

extern "C" void* jagged_fold_metadata_kernel() {
    return (void*)jaggedFoldMetadata;
}

extern "C" uint32_t jagged_fold_metadata_block_dim() {
    return BLOCK_DIM;
}

extern "C" uint32_t jagged_fold_metadata_section_size() {
    return SECTION_SIZE;
}
