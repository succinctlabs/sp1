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