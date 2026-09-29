#include "config.cuh"
#include "tracegen/jagged_tracegen/jagged.cuh"
#include "zerocheck/jagged_mle.cuh"

template <typename F>
__global__ void fixLastVariableJagged(
    const JaggedMle<DenseBuffer<F>> inputJaggedMle,
    JaggedMle<DenseBuffer<ext_t>> outputJaggedMle,
    uint32_t length,
    ext_t alpha) {

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < length;
         i += blockDim.x * gridDim.x) {
        inputJaggedMle.fixLastVariableTwoPadding(outputJaggedMle, i, alpha);
    }
}

// Folds the last two variables in one pass over the input (see
// `fixLastTwoVariablesTwoPadding`); `n_quads` is the input pair count / 2.
// Used by the zerocheck fused first-two-rounds, whose two challenges are
// both known before any fold happens.
template <typename F>
__global__ void fixLastTwoVariablesJagged(
    const JaggedMle<DenseBuffer<F>> inputJaggedMle,
    JaggedMle<DenseBuffer<ext_t>> outputJaggedMle,
    uint32_t n_quads,
    ext_t alpha_1,
    ext_t alpha_2) {

    for (size_t q = blockIdx.x * blockDim.x + threadIdx.x; q < n_quads;
         q += blockDim.x * gridDim.x) {
        inputJaggedMle.fixLastTwoVariablesTwoPadding(outputJaggedMle, q, alpha_1, alpha_2);
    }
}

__global__ void initializeJaggedInfo(
    JaggedMle<InfoBuffer> jaggedMle,
    const uint64_t* values,
    uint32_t length,
    uint32_t num_info) {
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < length;
         i += blockDim.x * gridDim.x) {
        uint32_t c = upper_bound_u32(jaggedMle.startIndices, num_info + 1, i) - 1;
        jaggedMle.denseData.data[i << 1] = values[c];
        jaggedMle.denseData.data[i << 1 | 1] = values[c];
        jaggedMle.colIndex[i] = c;
    }
}

__global__ void fixLastVariableJaggedInfo(
    const JaggedMle<InfoBuffer> inputJaggedMle,
    JaggedMle<InfoBuffer> outputJaggedMle,
    uint32_t length) {
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < length;
         i += blockDim.x * gridDim.x) {
        inputJaggedMle.fixLastVariableTwoPaddingInfo(outputJaggedMle, i);
    }
}

template <typename F>
__global__ void jaggedEvalChunked(
    const JaggedMle<DenseBuffer<F>> inputJaggedMle,
    const ext_t* __restrict__ row_coefficient,
    const ext_t* __restrict__ col_coefficient,
    uint32_t L,
    uint32_t num_cols,
    ext_t* __restrict__ output_evals) {

    inputJaggedMle.evaluate(row_coefficient, col_coefficient, L, num_cols, output_evals);
}

extern "C" void* initialize_jagged_info() { return (void*)initializeJaggedInfo; }

extern "C" void* fix_last_variable_jagged_felt() { return (void*)fixLastVariableJagged<felt_t>; }
extern "C" void* fix_last_variable_jagged_ext() { return (void*)fixLastVariableJagged<ext_t>; }
extern "C" void* fix_last_two_variables_jagged_felt() {
    return (void*)fixLastTwoVariablesJagged<felt_t>;
}
extern "C" void* fix_last_variable_jagged_info() { return (void*)fixLastVariableJaggedInfo; }

extern "C" void* jagged_eval_kernel_chunked_felt() { return (void*)jaggedEvalChunked<felt_t>; }
extern "C" void* jagged_eval_kernel_chunked_ext() { return (void*)jaggedEvalChunked<ext_t>; }