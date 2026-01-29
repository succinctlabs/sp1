#pragma once

#include <cstdint>

// Scan kernel for T with large sizeof(T).
namespace scan_large {
// TODO: make this a const parmaeter
const size_t SECTION_SIZE = 512;

template <typename T>
__device__ __inline__ void BrentKungScan(
    T* d_out,
    T* d_in,
    T* aux,
    size_t block_idx,
    size_t block_dim,
    size_t thread_idx,
    size_t n) {
    size_t i = 2 * block_idx * block_dim + thread_idx;
    if (i < n)
        aux[thread_idx] = d_in[i];
    if (i + block_dim < n)
        aux[thread_idx + block_dim] = d_in[i + block_dim];

#pragma unroll
    for (size_t stride = 1; stride <= block_dim; stride *= 2) {
        __syncthreads();
        size_t index = (thread_idx + 1) * stride * 2 - 1;
        if (index < SECTION_SIZE) {
            aux[index] += aux[index - stride];
        }
    }

#pragma unroll
    for (size_t stride = SECTION_SIZE / 4; stride > 0; stride /= 2) {
        __syncthreads();
        size_t index = (thread_idx + 1) * stride * 2 - 1;
        if (index + stride < SECTION_SIZE) {
            aux[index + stride] += aux[index];
        }
    }
    __syncthreads();
    if (i < n)
        d_out[i] = aux[thread_idx];
    if (i + block_dim < n)
        d_out[i + block_dim] = aux[thread_idx + block_dim];
}

template <typename T>
__global__ void SingleBlockScan(T* d_out, T* d_in, size_t n) {
    __shared__ T aux[SECTION_SIZE];
    size_t block_idx = blockIdx.x;
    size_t block_dim = blockDim.x;
    size_t thread_idx = threadIdx.x;
    BrentKungScan(d_out, d_in, aux, block_idx, block_dim, thread_idx, n);
}

template <typename T>
__global__ void
Scan(T* d_out, T* d_in, size_t n, T* scan_values, uint32_t* BlockCounter, uint32_t* flags) {
    // Set up a global block_id to make contiguous blocks which are scheduled sequentially.
    __shared__ size_t bid_s;
    if (threadIdx.x == 0) {
        bid_s = atomicAdd(BlockCounter, 1);
    }
    __syncthreads();
    size_t bid = bid_s;

    // Peform a scan on the local block.
    __shared__ T aux[SECTION_SIZE];
    BrentKungScan(d_out, d_in, aux, bid, blockDim.x, threadIdx.x, n);

    // Get the sum of the previous block, add it to the sum of the current block and broadcast it
    // to the next block.
    __shared__ T previous_sum;
    if (threadIdx.x == 0) {
        // Wait for the previous flag.
        while (atomicAdd(&flags[bid], 0) == 0) {
        };
        // Read previous partial sum.
        previous_sum = scan_values[bid];
        // Propagate current sum.
        scan_values[bid + 1] = aux[SECTION_SIZE - 1] + previous_sum;
        // Memory fence to ensure previous partial sum is visible to the next block.
        __threadfence();
        // Set flag.
        atomicAdd(&flags[bid + 1], 1);
    }
    __syncthreads();

    // Add the sum of the previous block to scan entries of the current block.
    size_t i = 2 * bid * blockDim.x + threadIdx.x;
    if (i < n)
        d_out[i] += previous_sum;
    if (i + blockDim.x < n)
        d_out[i + blockDim.x] += previous_sum;
}
} // namespace scan_large
