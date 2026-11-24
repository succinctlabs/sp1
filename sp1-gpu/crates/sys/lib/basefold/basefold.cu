#include "basefold/basefold.cuh"

#include "fields/kb31_t.cuh"
#include "fields/kb31_extension_t.cuh"

template <typename F, typename EF>
__global__ void batchKernel(F* input, EF* output, EF* betaPowers, size_t height, size_t width) {
    for (size_t rowIdx = blockIdx.x * blockDim.x + threadIdx.x; rowIdx < height;
         rowIdx += blockDim.x * gridDim.x) {
        EF accumulator = EF::zero();
        for (size_t colIdx = 0; colIdx < width; colIdx++) {
            accumulator += betaPowers[colIdx] * input[colIdx * height + rowIdx];
        }
        output[rowIdx] = accumulator;
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

// The committed leaves already group evaluations at x and -x. Fold each pair
// directly in evaluation form, keeping the four extension coordinates planar.
__global__ void foldCodeword(const kb31_t* leaves, kb31_t* out, uint32_t log_height,
                             kb31_t inverse_generator, kb31_extension_t half_beta) {
    const uint32_t height = 1u << log_height;
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= height) return;
    const uint32_t exponent = log_height ? (__brev(i) >> (32 - log_height)) : 0;
    const kb31_t inverse_x = inverse_generator ^ exponent;
    kb31_extension_t average, difference;
#pragma unroll
    for (int k = 0; k < kb31_extension_t::D; ++k) {
        const kb31_t even = leaves[size_t(k) * height + i];
        const kb31_t odd = leaves[size_t(k + kb31_extension_t::D) * height + i];
        average.value[k] = even + odd;
        average.value[k] >>= 1;
        difference.value[k] = even - odd;
    }
    const kb31_extension_t slope = half_beta * difference;
#pragma unroll
    for (int k = 0; k < kb31_extension_t::D; ++k)
        out[size_t(k) * height + i] = average.value[k] + slope.value[k] * inverse_x;
}

extern "C" void* fold_codeword_koala_bear_kernel() { return (void*)foldCodeword; }

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
