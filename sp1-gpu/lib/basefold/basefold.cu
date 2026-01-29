#include "basefold/basefold.cuh"

#include "fields/kb31_t.cuh"
#include "fields/kb31_extension_t.cuh"

template <typename F, typename EF>
__global__ void batchKernel(F* input, EF* output, EF* betaPowers, size_t height, size_t width) {
    for (size_t rowIdx = blockIdx.x * blockDim.x + threadIdx.x; rowIdx < height;
         rowIdx += blockDim.x * gridDim.x) {
        EF accumulator = EF::zero();
        for (size_t colIdx = 0; colIdx < width; colIdx++) {
            accumulator += input[colIdx * height + rowIdx] * betaPowers[colIdx];
        }
        output[rowIdx] += accumulator;
    }
}

extern "C" void* batch_koala_bear_base_ext_kernel() {
    return (void*)batchKernel<kb31_t, kb31_extension_t>;
}

template <typename F, typename EF>
__global__ void batchKernelFlattened(
    F* __restrict__ input,
    F* __restrict__ output,
    EF* betaPowers,
    size_t height,
    size_t width) {
    for (size_t rowIdx = blockIdx.x * blockDim.x + threadIdx.x; rowIdx < height;
         rowIdx += blockDim.x * gridDim.x) {
        EF accumulator = EF::zero();
        for (size_t colIdx = 0; colIdx < width; colIdx++) {
            accumulator += betaPowers[colIdx] * input[colIdx * height + rowIdx];
        }
        for (int k = 0; k < EF::D; k++) {
            output[k * height + rowIdx] += accumulator.value[k];
        }
    }
}

extern "C" void* batch_koala_bear_base_ext_kernel_flattened() {
    return (void*)batchKernelFlattened<kb31_t, kb31_extension_t>;
}

template <typename F, typename EF>
__global__ void
transposeEvenOdd(F* __restrict__ input, F* __restrict__ output, size_t outputHeight) {
    size_t inputHeight = outputHeight << 1;
    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < outputHeight;
         i += blockDim.x * gridDim.x) {
#pragma unroll
        for (size_t k = 0; k < EF::D; k++) {
            output[k * outputHeight + i] = input[k * inputHeight + (i << 1)];
            output[(k + EF::D) * outputHeight + i] = input[k * inputHeight + (i << 1) + 1];
        }
    }
}

extern "C" void* transpose_even_odd_koala_bear_base_ext_kernel() {
    return (void*)transposeEvenOdd<kb31_t, kb31_extension_t>;
}

template <typename F, typename EF>
__global__ void flattenToBase(EF* __restrict__ input, F* __restrict__ output, size_t height) {
    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {
        EF inputValue = EF::load(input, i);
#pragma unroll
        for (size_t k = 0; k < EF::D; k++) {
            output[k * height + i] = inputValue.value[k];
        }
    }
}

extern "C" void* flatten_to_base_koala_bear_base_ext_kernel() {
    return (void*)flattenToBase<kb31_t, kb31_extension_t>;
}