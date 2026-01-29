#include "sum_and_reduce/dot.cuh"
#include "sum_and_reduce/reduction.cuh"

template <typename F, typename BaseF>
__global__ void partialBlockInnerProductKernel(
    F* __restrict__ partial,
    F* __restrict__ A,
    BaseF* __restrict__ B,
    size_t width,
    size_t height) {
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
        op.evalAssign(thread_val, A[batchIdx * height + i] * B[batchIdx * height + i]);
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

extern "C" void* partial_inner_product_koala_bear_kernel() {
    return (void*)partialBlockInnerProductKernel<kb31_t, kb31_t>;
}

extern "C" void* partial_inner_product_koala_bear_extension_kernel() {
    return (void*)partialBlockInnerProductKernel<kb31_extension_t, kb31_extension_t>;
}

extern "C" void* partial_inner_product_koala_bear_base_extension_kernel() {
    return (void*)partialBlockInnerProductKernel<kb31_extension_t, kb31_t>;
}

template <typename EF, typename F>
__global__ void partialBlockDotKernel(
    EF* __restrict__ partial,
    F* __restrict__ A,
    EF* B,
    size_t width,
    size_t height) {
    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    AddOp<EF> op;

    EF thread_val = op.initial();

    size_t batchIdx = blockDim.y * blockIdx.y + threadIdx.y;
    if (batchIdx >= width) {
        return;
    }

    // Stride loop to accumulate partial sum
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {
        F a = F::load(A, batchIdx * height + i);
        EF b = EF::load(B, i);
        EF c = b * a;
        op.evalAssign(thread_val, c);
    }

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    EF* shared = reinterpret_cast<EF*>(memory);

    // // Warp-level reduction within tiles
    thread_val = partialBlockReduce(block, tile, thread_val, shared, op);

    // Write the result to the partial_sums array
    if (block.thread_rank() == 0) {
        EF::store(partial, batchIdx * gridDim.x + blockIdx.x, shared[0]);
    }
}

extern "C" void* partial_dot_koala_bear_kernel() {
    return (void*)partialBlockDotKernel<kb31_t, kb31_t>;
}

extern "C" void* partial_dot_koala_bear_extension_kernel() {
    return (void*)partialBlockDotKernel<kb31_extension_t, kb31_extension_t>;
}

extern "C" void* partial_dot_koala_bear_base_extension_kernel() {
    return (void*)partialBlockDotKernel<kb31_extension_t, kb31_t>;
}

template <typename F, typename EF>
__global__ void dotAlongShortDimensionKernel(
    EF* __restrict__ result,
    F* __restrict__ A,
    EF* B,
    size_t width,
    size_t height) {
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {
        EF acc = EF::zero();
        for (size_t j = 0; j < width; j++) {
            EF b = EF::load(B, j);
            F a = F::load(A, j * height + i);
            acc += b * a;
        }
        EF::store(result, i, acc);
    }
}

extern "C" void* dot_along_short_dimension_kernel_koala_bear_base_base() {
    return (void*)dotAlongShortDimensionKernel<kb31_t, kb31_t>;
}

extern "C" void* dot_along_short_dimension_kernel_koala_bear_base_extension() {
    return (void*)dotAlongShortDimensionKernel<kb31_t, kb31_extension_t>;
}

extern "C" void* dot_along_short_dimension_kernel_koala_bear_extension_extension() {
    return (void*)dotAlongShortDimensionKernel<kb31_extension_t, kb31_extension_t>;
}
