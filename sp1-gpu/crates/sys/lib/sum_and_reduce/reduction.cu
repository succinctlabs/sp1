#include "sum_and_reduce/reduction.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

#include "fields/kb31_extension_t.cuh"
#include "fields/kb31_t.cuh"

namespace cg = cooperative_groups;

template <typename F, typename TyOp>
__global__ void partialBlockReduceKernel(F* partial, F* A, size_t width, size_t height, TyOp op) {
    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    F thread_val = op.initial();

    size_t batchIdx = blockDim.y * blockIdx.y + threadIdx.y;
    if (batchIdx >= width) {
        return;
    }

    // Stride loop to accumulate partial sum
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {
        op.evalAssign(thread_val, A[batchIdx * height + i]);
    }

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    F* shared = reinterpret_cast<F*>(memory);

    // // Warp-level reduction within tiles
    thread_val = partialBlockReduce(block, tile, thread_val, shared, op);

    // Write the result to the partial_sums array
    if (block.thread_rank() == 0) {
        partial[batchIdx * gridDim.x + blockIdx.x] = shared[0];
    }
}

template <typename F, typename TyOp>
__global__ void blockReduce(F* A, F* result, size_t width, size_t height, TyOp op) {
    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    size_t batchIdx = blockDim.y * blockIdx.y + threadIdx.y;
    if (batchIdx >= width) {
        return;
    }

    F thread_val = op.initial();

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {
        op.evalAssign(thread_val, A[batchIdx * height + i]);
    }

    op.final_block_reduction_async(tile, &result[batchIdx], thread_val);
    block.sync();
}

//------------------------------------------------- sum

template <typename F>
__global__ void partialBlockSumKernel(F* partial, F* A, size_t width, size_t height) {
    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    AddOp<F> op;

    F thread_val = op.initial();

    size_t batchIdx = blockDim.y * blockIdx.y + threadIdx.y;
    if (batchIdx >= width) {
        return;
    }

    // Stride loop to accumulate partial sum
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {
        op.evalAssign(thread_val, A[batchIdx * height + i]);
    }

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    F* shared = reinterpret_cast<F*>(memory);

    // // Warp-level reduction within tiles
    thread_val = partialBlockReduce(block, tile, thread_val, shared, op);

    // Write the result to the partial_sums array
    if (block.thread_rank() == 0) {
        partial[batchIdx * gridDim.x + blockIdx.x] = shared[0];
    }
}

template <typename F>
__global__ void blockSum(F* A, F* result, size_t width, size_t height) {
    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    AddOp<F> op;

    size_t batchIdx = blockDim.y * blockIdx.y + threadIdx.y;
    if (batchIdx >= width) {
        return;
    }

    F thread_val = op.initial();

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {
        op.evalAssign(thread_val, A[batchIdx * height + i]);
    }

    op.final_block_reduction_async(tile, &result[batchIdx], thread_val);
    block.sync();
}

extern "C" void* koala_bear_sum_block_reduce_kernel() { return (void*)blockSum<kb31_t>; }

extern "C" void* koala_bear_sum_partial_block_reduce_kernel() {
    return (void*)partialBlockSumKernel<kb31_t>;
}

extern "C" void* koala_bear_extension_sum_block_reduce_kernel() {
    return (void*)blockSum<kb31_extension_t>;
}

extern "C" void* koala_bear_extension_sum_partial_block_reduce_kernel() {
    return (void*)partialBlockSumKernel<kb31_extension_t>;
}
