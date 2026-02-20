#include "logup_gkr/first_layer.cuh"
#include "logup_gkr/execution.cuh"

#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"
#include "tracegen/jagged_tracegen/jagged.cuh"

__global__ void logupGkrFixLastVariableFirstCircuitLayer(
    const JaggedMle<JaggedFirstGkrLayer> inputJaggedMle,
    JaggedMle<JaggedGkrLayer> outputJaggedMle,
    ext_t alpha) {

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < inputJaggedMle.denseData.height;
         i += blockDim.x * gridDim.x) {

        inputJaggedMle.fixLastVariableTwoPadding(outputJaggedMle, i, alpha);
    }
}

__global__ void fixAndSumFirstCircuitLayer(
    ext_t* __restrict__ univariate_result,
    const JaggedMle<JaggedFirstGkrLayer> inputJaggedMle,
    JaggedMle<JaggedGkrLayer> outputJaggedMle,
    const ext_t* __restrict__ eqRow,
    const ext_t* __restrict__ eqInteraction,
    const ext_t lambda,
    ext_t alpha) {

    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();
    ext_t eqSum = ext_t::zero();
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < inputJaggedMle.denseData.height >> 1;
         i += blockDim.x * gridDim.x) {
        // Process one fixLastVariable. Since height is always even, this is guaranteed to not
        // require any padding checks.
        size_t firstIdx = i << 1;
        inputJaggedMle.fixLastVariableUnchecked(outputJaggedMle, firstIdx, alpha);

        // The second fix_last_variable could by trying to process the end of the row. We are
        // guaranteed to be able to access the end of this row, but we need to make sure that the
        // next row has even length too.
        size_t secondIdx = firstIdx + 1;

        size_t restrictedIndex =
            inputJaggedMle.fixLastVariableTwoPadding(outputJaggedMle, secondIdx, alpha);

        size_t outputIndex = restrictedIndex >> 1;

        // Now set up the sum_as_poly.
        size_t colIdx = outputJaggedMle.colIndex[outputIndex];
        size_t startIdx = outputJaggedMle.startIndices[colIdx];
        SumAsPolyResult result = sumAsPolyCircuitLayerInner(
            outputJaggedMle.denseData.layer,
            colIdx,
            startIdx,
            eqRow,
            eqInteraction,
            lambda,
            outputJaggedMle.denseData.height,
            outputIndex);

        evalZero += result.evalZero;
        evalHalf += result.evalHalf;
        eqSum += result.eqSum;
    }

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);
    ext_t evalZeroblockSum = partialBlockReduce(block, tile, evalZero, shared);
    ext_t evalHalfblockSum = partialBlockReduce(block, tile, evalHalf, shared);
    ext_t eqSumBlockSum = partialBlockReduce(block, tile, eqSum, shared);

    if (threadIdx.x == 0) {
        ext_t::store(univariate_result, blockIdx.x, evalZeroblockSum);
        ext_t::store(univariate_result, gridDim.x + blockIdx.x, evalHalfblockSum);
        ext_t::store(univariate_result, 2 * gridDim.x + blockIdx.x, eqSumBlockSum);
    }
}

__global__ void logupGkrSumAsPolyFirstCircuitLayer(
    ext_t* __restrict__ result,
    const JaggedMle<JaggedFirstGkrLayer> inputJaggedMle,
    const ext_t* __restrict__ eqRow,
    const ext_t* __restrict__ eqInteraction,
    const ext_t lambda) {

    felt_t* inputNumerator = inputJaggedMle.denseData.numeratorValues;
    ext_t* inputDenominator = inputJaggedMle.denseData.denominatorValues;
    uint32_t* colIndex = inputJaggedMle.colIndex;
    uint32_t* startIndices = inputJaggedMle.startIndices;
    size_t height = inputJaggedMle.denseData.height;

    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();
    ext_t eqSum = ext_t::zero();
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {
        size_t colIdx = colIndex[i];
        size_t startIdx = startIndices[colIdx];
        size_t rowIdx = i - startIdx;

        size_t eqRowZeroIdx = rowIdx << 1;
        size_t eqRowOneIdx = eqRowZeroIdx + 1;

        ext_t eqInteractionValue = ext_t::load(eqInteraction, colIdx);
        ext_t eqRowZeroValue = ext_t::load(eqRow, eqRowZeroIdx);
        ext_t eqRowOneValue = ext_t::load(eqRow, eqRowOneIdx);

        ext_t eqValueZero = eqRowZeroValue * eqInteractionValue;
        ext_t eqValueOne = eqRowOneValue * eqInteractionValue;
        ext_t eqValueHalf = eqValueZero + eqValueOne;

        eqSum += eqValueHalf;

        size_t zeroIdx = i << 1;
        size_t oneIdx = zeroIdx + 1;

        FirstLayerCircuitValues valuesZero =
            FirstLayerCircuitValues::load(inputNumerator, inputDenominator, zeroIdx, height);
        FirstLayerCircuitValues valuesOne =
            FirstLayerCircuitValues::load(inputNumerator, inputDenominator, oneIdx, height);

        // Compute the values at the point 1 /2 (times a factor of 2)
        FirstLayerCircuitValues valuesHalf;
        valuesHalf.numeratorZero = valuesZero.numeratorZero + valuesOne.numeratorZero;
        valuesHalf.numeratorOne = valuesZero.numeratorOne + valuesOne.numeratorOne;
        valuesHalf.denominatorZero = valuesZero.denominatorZero + valuesOne.denominatorZero;
        valuesHalf.denominatorOne = valuesZero.denominatorOne + valuesOne.denominatorOne;

        // Compute the sumcheck sum values and add to the running aggregate
        evalZero += valuesZero.sumAsPoly(lambda, eqValueZero);
        evalHalf += valuesHalf.sumAsPoly(lambda, eqValueHalf);
    }

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);
    ext_t evalZeroblockSum = partialBlockReduce(block, tile, evalZero, shared);
    ext_t evalHalfblockSum = partialBlockReduce(block, tile, evalHalf, shared);
    ext_t eqSumBlockSum = partialBlockReduce(block, tile, eqSum, shared);

    if (threadIdx.x == 0) {
        ext_t::store(result, blockIdx.x, evalZeroblockSum);
        ext_t::store(result, gridDim.x + blockIdx.x, evalHalfblockSum);
        ext_t::store(result, 2 * gridDim.x + blockIdx.x, eqSumBlockSum);
    }
}

__global__ void LogUpFirstLayerTransitionKernel(
    const JaggedMle<JaggedFirstGkrLayer> inputJaggedMle,
    JaggedMle<JaggedGkrLayer> outputJaggedMle) {

    size_t height = inputJaggedMle.denseData.height;

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {

        circuitTransitionTwoPadding(inputJaggedMle, outputJaggedMle, i);
    }
}

extern "C" void* logup_gkr_fix_and_sum_first_layer() {
    return (void*)fixAndSumFirstCircuitLayer;
}

extern "C" void* logup_gkr_fix_last_variable_first_layer() {
    return (void*)logupGkrFixLastVariableFirstCircuitLayer;
}

extern "C" void* logup_gkr_sum_as_poly_first_layer() {
    return (void*)logupGkrSumAsPolyFirstCircuitLayer;
}

extern "C" void* logup_gkr_first_layer_transition() {
    return (void*)LogUpFirstLayerTransitionKernel;
}
