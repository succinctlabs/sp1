#include "mle/fixlastvariable.cuh"
#include "config.cuh"
#include "mle/fixlastvariable.cuh"

template <typename F, typename EF>
__global__ void fixLastVariable(
    const F* input,
    EF* __restrict__ output,
    F* paddingValues,
    EF alpha,
    size_t inputHeight,
    size_t width) {
    size_t outputHeight = (inputHeight + 1) >> 1;
    bool padding = inputHeight & 1;
    for (size_t j = blockDim.y * blockIdx.y + threadIdx.y; j < width; j += blockDim.y * gridDim.y) {
        for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < outputHeight;
             i += blockDim.x * gridDim.x) {
            F zeroValue = F::load(input, j * inputHeight + (i << 1));
            F oneValue;
            if (padding) {
                if (i < outputHeight - 1) {
                    oneValue = F::load(input, j * inputHeight + (i << 1) + 1);
                } else {
                    oneValue = paddingValues[j];
                }
            } else {
                oneValue = F::load(input, j * inputHeight + (i << 1) + 1);
            }
            // Compute value = zeroValue * (1 - alpha) + oneValue * alpha
            EF value = alpha.interpolateLinear(oneValue, zeroValue);
            EF::store(output, j * outputHeight + i, value);
        }
    }
}

extern "C" void* fix_last_variable_felt_ext_kernel() {
    return (void*)fixLastVariable<felt_t, ext_t>;
}

extern "C" void* fix_last_variable_ext_ext_kernel() { return (void*)fixLastVariable<ext_t, ext_t>; }



template <typename F, typename EF>
__global__ void fixLastVariableConstantPadding(
    const F* input,
    EF* __restrict__ output,
    F paddingValue,
    EF alpha,
    size_t inputHeight,
    size_t width) {
    size_t outputHeight = (inputHeight + 1) >> 1;
    bool padding = inputHeight & 1;
    for (size_t j = blockDim.y * blockIdx.y + threadIdx.y; j < width; j += blockDim.y * gridDim.y) {
        for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < outputHeight;
             i += blockDim.x * gridDim.x) {
            F zeroValue = F::load(input, j * inputHeight + (i << 1));
            F oneValue;
            if (padding) {
                if (i < outputHeight - 1) {
                    oneValue = F::load(input, j * inputHeight + (i << 1) + 1);
                } else {
                    oneValue = paddingValue;
                }
            } else {
                oneValue = F::load(input, j * inputHeight + (i << 1) + 1);
            }
            // Compute value = zeroValue * (1 - alpha) + oneValue * alpha
            EF value = alpha.interpolateLinear(oneValue, zeroValue);
            EF::store(output, j * outputHeight + i, value);
        }
    }
}


template <typename F, typename EF>
__global__ void fixLastVariableZeroPadding(
    const F* input,
    EF* __restrict__ output,
    EF alpha,
    size_t inputHeight,
    size_t width) {
    size_t outputHeight = (inputHeight + 1) >> 1;
    bool padding = inputHeight & 1;
    for (size_t j = blockDim.y * blockIdx.y + threadIdx.y; j < width; j += blockDim.y * gridDim.y) {
        for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < outputHeight;
             i += blockDim.x * gridDim.x) {
            F zeroValue = F::load(input, j * inputHeight + (i << 1));
            F oneValue;
            if (padding) {
                if (i < outputHeight - 1) {
                    oneValue = F::load(input, j * inputHeight + (i << 1) + 1);
                } else {
                    oneValue = F::zero();
                }
            } else {
                oneValue = F::load(input, j * inputHeight + (i << 1) + 1);
            }
            // Compute value = zeroValue * (1 - alpha) + oneValue * alpha
            EF value = alpha.interpolateLinear(oneValue, zeroValue);
            EF::store(output, j * outputHeight + i, value);
        }
    }
}


extern "C" void* mle_fix_last_variable_koala_bear_base_extension_constant_padding() {
    return (void*)fixLastVariableConstantPadding<kb31_t, kb31_extension_t>;
}

extern "C" void* mle_fix_last_variable_koala_bear_ext_ext_constant_padding() {
    return (void*)fixLastVariableConstantPadding<kb31_extension_t, kb31_extension_t>;
}

extern "C" void* mle_fix_last_variable_koala_bear_ext_ext_zero_padding() {
    return (void*)fixLastVariableZeroPadding<kb31_extension_t, kb31_extension_t>;
}