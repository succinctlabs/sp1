#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

template <typename F>
/// @brief Reduce the columns of input array into the output array
/// @param input The input array of dimension (width, height)
/// @param output The output array of dimension (width, num_blocks)
/// @param width The width of the input array
/// @param height The height of the input array
/// @note The output array is of dimension (width) and contains the sum of each column of the input
/// array.
///       The num_blocks is the number of blocks in the grid.
__global__ void reduceKernel(F* input, F* output, size_t width, size_t height) {

    // Get the block and tile
    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    F* shared = reinterpret_cast<F*>(memory);

    // Stride loop on columns
    for (size_t j = blockIdx.y * blockDim.y + threadIdx.y; j < width; j += blockDim.y * gridDim.y) {
        // Initialize the partial sum
        F threadVal = F::zero();

        // Collect the sum from current row and all strides (if any)
        for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < height;
             i += blockDim.x * gridDim.x) {
            threadVal += input[j * height + i];
        }

        // Compute the sum for the current block in shared memory
        partialBlockReduce(block, tile, threadVal, shared);

        // Write the result to the output array
        if (block.thread_rank() == 0) {
            output[j * gridDim.x + blockIdx.x] = shared[0];
        }
    }
}

extern "C" void* reduce_kernel_felt() { return reinterpret_cast<void*>(reduceKernel<felt_t>); }

extern "C" void* reduce_kernel_ext() { return reinterpret_cast<void*>(reduceKernel<ext_t>); }

// Test-only kernel: launched as a single block with `len` threads (where
// `len <= blockDim.x`). Each thread loads `input[threadIdx.x]` (or zero if out
// of range) and `partialBlockReduce` reduces them. Result goes to `output[0]`.
//
// Used by `examples/partial_block_reduce_test.rs` to exercise non-power-of-2
// warp counts (e.g. 96 threads = 3 warps, 160 = 5, 224 = 7, 288 = 9).
__global__ void partialBlockReduceTestKernel(const felt_t* input, felt_t* output, uint32_t len) {
    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    extern __shared__ unsigned char memory[];
    felt_t* shared = reinterpret_cast<felt_t*>(memory);

    felt_t val = (threadIdx.x < len) ? input[threadIdx.x] : felt_t::zero();
    felt_t block_sum = partialBlockReduce(block, tile, val, shared);

    if (threadIdx.x == 0) {
        output[0] = block_sum;
    }
}

extern "C" void* partial_block_reduce_test_kernel_felt() {
    return reinterpret_cast<void*>(partialBlockReduceTestKernel);
}