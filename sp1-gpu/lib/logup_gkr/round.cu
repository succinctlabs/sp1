#include "sum_and_reduce/reduce.cuh"
#include "tracegen/jagged_tracegen/jagged.cuh"
#include "logup_gkr/round.cuh"
#include "config.cuh"

#include <cstdio>

/// Currently not used.
__global__ void fixLastVariableCircuitLayer(
    ext_t* __restrict__ layer,
    const uint32_t* __restrict__ colIndex,
    const uint32_t* __restrict__ startIndices,
    ext_t alpha,
    ext_t* __restrict__ outputLayer,
    uint32_t* __restrict__ outputcolIndex,
    const uint32_t* __restrict__ nextLayerStartIndices,
    const size_t height,
    const size_t outputHeight) {

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {
        size_t colIdx = colIndex[i] & 0x00FFFFFF;
        size_t dimension = colIndex[i] >> 24;
        size_t currentStartIndex = startIndices[colIdx];
        size_t interactionHeight = startIndices[colIdx + 1] - currentStartIndex;
        fixLastVariableCircuitLayerInner(
            layer,
            colIdx,
            dimension,
            currentStartIndex,
            interactionHeight,
            alpha,
            outputLayer,
            outputcolIndex,
            nextLayerStartIndices,
            height,
            outputHeight,
            i);
    }
}

__global__ void sumAsPolyCircuitLayer(
    ext_t* __restrict__ result,
    const JaggedMle<JaggedGkrLayer> inputJaggedMle,
    const ext_t* __restrict__ eqRow,
    const ext_t* __restrict__ eqInteraction,
    const ext_t lambda) {

    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();
    ext_t eqSum = ext_t::zero();

    size_t height = inputJaggedMle.denseData.height;
    uint32_t* colIndex = inputJaggedMle.colIndex;
    uint32_t* startIndices = inputJaggedMle.startIndices;
    ext_t* layer = inputJaggedMle.denseData.layer;
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {
        size_t colIdx = colIndex[i];
        size_t startIdx = startIndices[colIdx];
        SumAsPolyResult result = sumAsPolyCircuitLayerInner(
            layer,
            colIdx,
            startIdx,
            eqRow,
            eqInteraction,
            lambda,
            height,
            i);
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
        ext_t::store(result, blockIdx.x, evalZeroblockSum);
        ext_t::store(result, gridDim.x + blockIdx.x, evalHalfblockSum);
        ext_t::store(result, 2 * gridDim.x + blockIdx.x, eqSumBlockSum);
    }
}

__global__ void firstSumAsPolyCircuitLayer(
    ext_t* __restrict__ result,
    const JaggedMle<JaggedGkrLayer> inputJaggedMle,
    const ext_t* __restrict__ eqRow,
    const ext_t* __restrict__ eqInteraction,
    const ext_t lambda) {

    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();
    ext_t eqSum = ext_t::zero();

    size_t height = inputJaggedMle.denseData.height;
    uint32_t* colIndex = inputJaggedMle.colIndex;
    uint32_t* startIndices = inputJaggedMle.startIndices;
    ext_t* layer = inputJaggedMle.denseData.layer;

    for (size_t j = blockIdx.x * blockDim.x + threadIdx.x; j < height >> 1;
         j += blockDim.x * gridDim.x) {

        size_t i = j << 1;

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

        // Add the eqValue to the running aggregate
        eqSum += eqValueHalf;

        // Load the numerator and denominator values
        size_t zeroIdx = i << 1;
        size_t oneIdx = (i << 1) + 1;
        CircuitValues valuesZero;
        CircuitValues valuesOne;
        valuesZero = CircuitValues::load(layer, zeroIdx, height);
        valuesOne = CircuitValues::load(layer, oneIdx, height);

        // Compute the values at the point 1/2 (times a factor of 2)
        CircuitValues valuesHalf;
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

__global__ void fixLastVariableLastCircuitLayer(
    const ext_t* __restrict__ layer,
    ext_t alpha,
    ext_t* __restrict__ output,
    const size_t height) {
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {
        size_t zeroIdx = i << 1;
        size_t oneIdx = (i << 1) + 1;
        CircuitValues valuesZero = CircuitValues::load(layer, zeroIdx, height * 2);
        CircuitValues valuesOne = CircuitValues::load(layer, oneIdx, height * 2);
        CircuitValues values = CircuitValues::fix_last_variable(valuesZero, valuesOne, alpha);

        // Store the restricted values
        ext_t::store(output, i, values.numeratorZero);
        ext_t::store(output, height + i, values.numeratorOne);
        ext_t::store(output, 2 * height + i, values.denominatorZero);
        ext_t::store(output, 3 * height + i, values.denominatorOne);
    }
}

__global__ void sumAsPolyInteractionsLayer(
    ext_t* __restrict__ result,
    ext_t* __restrict__ layer,
    const ext_t* __restrict__ eqPoly,
    const ext_t lambda,
    const size_t height,
    const size_t outputHeight) {

    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();
    ext_t eqSum = ext_t::zero();

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < outputHeight;
         i += blockDim.x * gridDim.x) {
        SumAsPolyResult result = sumAsPolyInteractionLayerInner(layer, eqPoly, lambda, height, i);
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
        ext_t::store(result, blockIdx.x, evalZeroblockSum);
        ext_t::store(result, gridDim.x + blockIdx.x, evalHalfblockSum);
        ext_t::store(result, 2 * gridDim.x + blockIdx.x, eqSumBlockSum);
    }
}

__global__ void fixLastVariableInteractionsLayer(
    const ext_t* input,
    ext_t* __restrict__ output,
    ext_t alpha,
    size_t height,
    size_t outputHeight) {
    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < outputHeight;
         i += blockDim.x * gridDim.x) {
        fixLastVariableInteractionsLayerInner(input, output, alpha, height, outputHeight, i);
    }
}


// Invoke this one during normal circuit layers
__global__ void fixAndSumCircuitLayer(
    ext_t* __restrict__ univariate_result,
    const JaggedMle<JaggedGkrLayer> inputJaggedMle,
    JaggedMle<JaggedGkrLayer> outputJaggedMle,
    ext_t alpha,
    const ext_t* __restrict__ eqRow,
    const ext_t* __restrict__ eqInteraction,
    const ext_t lambda) {

    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();
    ext_t eqSum = ext_t::zero();

    // Height is always even, so no need to take ceiling here.
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

// Invoke this one for the last circuit layer, when you transition to interactions.
__global__ void fixAndSumLastCircuitLayer(
    ext_t* __restrict__ univariate_result,
    const JaggedGkrLayer inputJaggedMle,
    ext_t alpha,
    ext_t* __restrict__ output,
    const ext_t* __restrict__ eqInteraction,
    const ext_t lambda) {

    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();
    ext_t eqSum = ext_t::zero();

    size_t height = inputJaggedMle.height >> 1;
    ext_t* layer = inputJaggedMle.layer;

    size_t outputHeight = (height + 1) >> 1;

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < outputHeight;
         i += blockDim.x * gridDim.x) {

        // We need to fix 2 pairs from the input, and combine their values with sum_as_poly.
        // Since every other value from the input is padding, we index into the input layer
        // as follows:
        //
        // zeroIdx_0 = 8i
        // oneIdx_0 = 8i + 1
        // zeroIdx_1 = 8i + 4
        // oneIdx_1 = 8i + 5
        //
        // Store the first fix last variable pair at index 2i, and the second at index 2i + 1.
        size_t zeroIdx = i << 3;
        size_t oneIdx = (i << 3) + 1;

        // Fix last variable for the actual layer
        CircuitValues valuesZero = CircuitValues::load(layer, zeroIdx, height * 2);
        CircuitValues valuesOne = CircuitValues::load(layer, oneIdx, height * 2);
        CircuitValues values = CircuitValues::fix_last_variable(valuesZero, valuesOne, alpha);

        size_t outputIndex = i << 1;

        // Store the restricted values
        ext_t::store(output, outputIndex, values.numeratorZero);
        ext_t::store(output, height + outputIndex, values.numeratorOne);
        ext_t::store(output, 2 * height + outputIndex, values.denominatorZero);
        ext_t::store(output, 3 * height + outputIndex, values.denominatorOne);

        zeroIdx = (i << 3) + 4;
        oneIdx = (i << 3) + 5;

        // We check if the second fix_last_variable is within bounds. We don't need to materialize
        // padding if not, because sum_as_poly handles it internally.
        if (oneIdx < height << 2) {
            valuesZero = CircuitValues::load(layer, zeroIdx, height * 2);
            valuesOne = CircuitValues::load(layer, oneIdx, height * 2);
            values = CircuitValues::fix_last_variable(valuesZero, valuesOne, alpha);

            outputIndex = (i << 1) + 1;
            // Store the restricted values
            ext_t::store(output, outputIndex, values.numeratorZero);
            ext_t::store(output, height + outputIndex, values.numeratorOne);
            ext_t::store(output, 2 * height + outputIndex, values.denominatorZero);
            ext_t::store(output, 3 * height + outputIndex, values.denominatorOne);
        }

        // Now set up the sum_as_poly.
        SumAsPolyResult result =
            sumAsPolyInteractionLayerInner(output, eqInteraction, lambda, height, i);
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

// Invoke this one for interactions layers
__global__ void fixAndSumInteractionsLayer(
    ext_t* __restrict__ univariate_result,
    const ext_t* input,
    ext_t* __restrict__ output,
    ext_t alpha,
    size_t height,
    size_t outputHeight,
    const ext_t* eqInteraction,
    const ext_t lambda) {

    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();
    ext_t eqSum = ext_t::zero();

    size_t halfOutputHeight = (outputHeight + 1) >> 1;
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < halfOutputHeight;
         i += blockDim.x * gridDim.x) {

        size_t firstIdx = i << 1;
        size_t secondIdx = (i << 1) + 1;

        // Fix last variable for the actual layer. TODO: this has some padding checks that aren't
        // needed.
        fixLastVariableInteractionsLayerInner(input, output, alpha, height, outputHeight, firstIdx);

        // Todo: instead of checking padding conditions twice here ad in sumAsPoly, we should do it
        // once.
        if (secondIdx < outputHeight) {
            fixLastVariableInteractionsLayerInner(
                input,
                output,
                alpha,
                height,
                outputHeight,
                secondIdx);
        }

        // Now set up the sum_as_poly. Padding is handled in here.
        SumAsPolyResult result =
            sumAsPolyInteractionLayerInner(output, eqInteraction, lambda, outputHeight, i);

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

extern "C" void* logup_gkr_sum_as_poly_circuit_layer() {
    return (void*)sumAsPolyCircuitLayer;
}

extern "C" void* logup_gkr_first_sum_as_poly_circuit_layer() {
    return (void*)firstSumAsPolyCircuitLayer;
}

extern "C" void* logup_gkr_fix_last_variable_circuit_layer() {
    return (void*)fixLastVariableCircuitLayer;
}

extern "C" void* logup_gkr_fix_last_variable_last_circuit_layer() {
    return (void*)fixLastVariableLastCircuitLayer;
}

extern "C" void* logup_gkr_sum_as_poly_interactions_layer() {
    return (void*)sumAsPolyInteractionsLayer;
}

extern "C" void* logup_gkr_fix_last_variable_interactions_layer() {
    return (void*)fixLastVariableInteractionsLayer;
}

extern "C" void* logup_gkr_fix_and_sum_circuit_layer() { return (void*)fixAndSumCircuitLayer; }

extern "C" void* logup_gkr_fix_and_sum_last_circuit_layer() {
    return (void*)fixAndSumLastCircuitLayer;
}

extern "C" void* logup_gkr_fix_and_sum_interactions_layer() {
    return (void*)fixAndSumInteractionsLayer;
}
