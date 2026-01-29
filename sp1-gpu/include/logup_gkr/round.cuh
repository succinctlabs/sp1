#pragma once

#include "config.cuh"
#include <cstddef>
extern "C" void* logup_gkr_sum_as_poly_circuit_layer();
extern "C" void* logup_gkr_fix_last_variable_circuit_layer();
extern "C" void* logup_gkr_fix_last_variable_last_circuit_layer();
extern "C" void* logup_gkr_sum_as_poly_interactions_layer();
extern "C" void* logup_gkr_fix_last_variable_interactions_layer();

#include <stdint.h>
#include <stdio.h>

struct CircuitValues {
  public:
    ext_t numeratorZero;
    ext_t numeratorOne;
    ext_t denominatorZero;
    ext_t denominatorOne;

  public:
    static __device__ __forceinline__ CircuitValues load(ext_t* layer, size_t i, size_t height) {
        CircuitValues values;
        // Load the numerator and denominator values
        //  numerator[i] = layer[0, i]
        //  numerator[i + 2 * height] = layer[2, i]
        //  denominator[i] = layer[4, i]
        //  denominator[i + 2 * height] = layer[6, i]

        // height is half of the number of entries in the layer, because even and odd indices belong
        // to the same row, since each row has to be even length.

        values.numeratorZero = ext_t::load(layer, i);
        values.numeratorOne = ext_t::load(layer, 2 * height + i);
        values.denominatorZero = ext_t::load(layer, 4 * height + i);
        values.denominatorOne = ext_t::load(layer, 6 * height + i);

        return values;
    }

    static __device__ __forceinline__ CircuitValues
    load(const ext_t* layer, size_t i, size_t height) {
        CircuitValues values;
        // Load the numerator and denominator values
        //  numerator[i] = layer[0, i]
        //  numerator[i + 2 * height] = layer[2, i]
        //  denominator[i] = layer[4, i]
        //  denominator[i + 2 * height] = layer[6, i]

        // height is half of the number of entries in the layer, because even and odd indices belong
        // to the same row.

        values.numeratorZero = ext_t::load(layer, i);
        values.numeratorOne = ext_t::load(layer, 2 * height + i);
        values.denominatorZero = ext_t::load(layer, 4 * height + i);
        values.denominatorOne = ext_t::load(layer, 6 * height + i);

        return values;
    }

    static __device__ __forceinline__ CircuitValues paddingValues() {
        CircuitValues values;
        values.numeratorZero = ext_t::zero();
        values.numeratorOne = ext_t::zero();
        values.denominatorZero = ext_t::one();
        values.denominatorOne = ext_t::one();
        return values;
    }

    static __device__ __forceinline__ CircuitValues
    fix_last_variable(CircuitValues zeroValues, CircuitValues oneValues, ext_t alpha) {
        CircuitValues values;
        values.numeratorZero =
            alpha.interpolateLinear(oneValues.numeratorZero, zeroValues.numeratorZero);
        values.numeratorOne =
            alpha.interpolateLinear(oneValues.numeratorOne, zeroValues.numeratorOne);
        values.denominatorZero =
            alpha.interpolateLinear(oneValues.denominatorZero, zeroValues.denominatorZero);
        values.denominatorOne =
            alpha.interpolateLinear(oneValues.denominatorOne, zeroValues.denominatorOne);
        return values;
    }

    __device__ __forceinline__ void store(ext_t* layer, size_t i, size_t height) {
        // Store the indices at entry [d, restrictedIndex]. This translates
        // to the index of the outut layer given by: d * 2 * height + restrictedIndex
        // where d = 0,1 for numerator_0, numerator_1, and values and d = 2,3 for
        // denominator_0, denominator_1 and values respectively.

        ext_t::store(layer, i, numeratorZero);
        ext_t::store(layer, 2 * height + i, numeratorOne);
        ext_t::store(layer, 4 * height + i, denominatorZero);
        ext_t::store(layer, 6 * height + i, denominatorOne);
    }

    /// Compute the sumcheck sum values
    __device__ __forceinline__ ext_t sumAsPoly(ext_t lambda, ext_t eqValue) {
        ext_t numerator = numeratorZero * denominatorOne + numeratorOne * denominatorZero;
        ext_t denominator = denominatorZero * denominatorOne;
        return eqValue * (numerator * lambda + denominator);
    }
};

/// A GKR layer.
struct JaggedGkrLayer {

    using OutputDenseData = JaggedGkrLayer;

  public:
    /// numerator_0 || numerator_1 || denominator_0 || denominator_1 , all of these are dense and
    /// the same length.
    ext_t* layer;
    /// Half of the length of each section.
    size_t height;

    __forceinline__ __device__ void fixLastVariable(
        JaggedGkrLayer& other,
        size_t restrictedIdx,
        size_t zeroIdx,
        size_t oneIdx,
        ext_t alpha) const {

        CircuitValues valuesZero = CircuitValues::load(layer, zeroIdx, height);
        CircuitValues valuesOne = CircuitValues::load(layer, oneIdx, height);
        CircuitValues values = CircuitValues::fix_last_variable(valuesZero, valuesOne, alpha);

        values.store(other.layer, restrictedIdx, other.height);
    }

    __forceinline__ __device__ void pad(JaggedGkrLayer& other, size_t restrictedIdx) const {
        CircuitValues values = CircuitValues::paddingValues();
        values.store(other.layer, restrictedIdx, other.height);
    }

    __forceinline__ __device__ void
    circuitTransition(JaggedGkrLayer& other, size_t restrictedIdx, size_t zeroIdx, size_t oneIdx)
        const {

        CircuitValues values;

        CircuitValues valuesZero = CircuitValues::load(layer, zeroIdx, height);
        CircuitValues valuesOne = CircuitValues::load(layer, oneIdx, height);
        values.numeratorZero = valuesZero.numeratorZero * valuesZero.denominatorOne +
                               valuesZero.numeratorOne * valuesZero.denominatorZero;
        values.denominatorZero = valuesZero.denominatorZero * valuesZero.denominatorOne;
        values.numeratorOne = valuesOne.numeratorZero * valuesOne.denominatorOne +
                              valuesOne.numeratorOne * valuesOne.denominatorZero;
        values.denominatorOne = valuesOne.denominatorZero * valuesOne.denominatorOne;

        values.store(other.layer, restrictedIdx, other.height);
    }
};


// i is expected to be between 0 and height.
// returns the output index
__device__ __forceinline__ size_t fixLastVariableCircuitLayerInner(
    ext_t* __restrict__ layer,
    size_t colIdx,
    size_t dimension,
    size_t currentStartIndex, // startIdx[colIdx]
    size_t interactionHeight, // startIdx[colIdx + 1] - startIdx[colIdx]
    ext_t alpha,
    ext_t* __restrict__ outputLayer,
    uint32_t* __restrict__ outputcolIndex,
    const uint32_t* __restrict__ nextLayerStartIndices,
    const size_t height,
    const size_t outputHeight,
    size_t i) {

    // The index within the the row.
    size_t rowIdx = i - currentStartIndex;

    size_t zeroIdx = i << 1;
    size_t oneIdx = (i << 1) + 1;

    CircuitValues valuesZero = CircuitValues::load(layer, zeroIdx, height);
    CircuitValues valuesOne = CircuitValues::load(layer, oneIdx, height);
    CircuitValues values = CircuitValues::fix_last_variable(valuesZero, valuesOne, alpha);
    // Store the restricted values
    size_t parity = rowIdx & 1;
    size_t restrictedRowIdx = rowIdx;
    size_t restrictedIndex = (nextLayerStartIndices[colIdx] << 1) + restrictedRowIdx;

    // Store the restricted values
    values.store(outputLayer, restrictedIndex, outputHeight);

    uint32_t outputDimension;
    // If the dimension is 0, we have exhausted the real variables and therefore
    // in the padding region, thus we need to account for the value at 1 to be
    // equal to the padding value.
    if (dimension == 1) {
        outputDimension = 1;
        CircuitValues paddingValues = CircuitValues::paddingValues();
        paddingValues.store(outputLayer, restrictedIndex + 1, outputHeight);
    } else {
        outputDimension = dimension - 1;
    }

    size_t isOdd = interactionHeight & 1;

    bool isLast = (interactionHeight - 1) == rowIdx;

    if (isOdd && isLast) {
        // If the size of this current row is odd, and we're the last thread in the row, then we
        // need to add a padding value.
        CircuitValues paddingValues = CircuitValues::paddingValues();
        paddingValues.store(outputLayer, restrictedIndex + 1, outputHeight);
    }

    // Write the output interaction data and dimension. Do it only once per pair
    // of points.
    if (parity == 0) {
        uint32_t outputInteractionValue = colIdx + (outputDimension << 24);
        outputcolIndex[restrictedIndex >> 1] = outputInteractionValue;
    }
    return restrictedIndex >> 1;
}

// Result structure for returning multiple values from sum as poly.
struct SumAsPolyResult {
    ext_t evalZero;
    ext_t evalHalf;
    ext_t eqSum;
};

// Inner sum as poly circuit layer
// Doesn't do the actual summing, just does the pairwise sums, and the eq sum
__device__ __forceinline__ SumAsPolyResult sumAsPolyCircuitLayerInner(
    const ext_t* __restrict__ layer,
    size_t colIdx,
    size_t startIdx, // 0 .. height
    const ext_t* __restrict__ eqRow,
    const ext_t* __restrict__ eqInteraction,
    const ext_t lambda,
    const size_t height,
    size_t i) { // 0 .. height

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
    ext_t eqSum = eqValueHalf;

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
    ext_t evalZero = valuesZero.sumAsPoly(lambda, eqValueZero);
    ext_t evalHalf = valuesHalf.sumAsPoly(lambda, eqValueHalf);

    return SumAsPolyResult{evalZero, evalHalf, eqSum};
}

__device__ __forceinline__ void fixLastVariableInteractionsLayerInner(
    const ext_t* input,
    ext_t* __restrict__ output,
    ext_t alpha,
    size_t height,
    size_t outputHeight,
    size_t i) {

    bool padding = height & 1;
    // The indices for the values at (i, 0) and (i, 1)
    size_t zeroIdx = i << 1;
    size_t oneIdx = (i << 1) + 1;

    // Load zero values
    CircuitValues valuesZero;
    valuesZero.numeratorZero = ext_t::load(input, zeroIdx);
    valuesZero.numeratorOne = ext_t::load(input, height + zeroIdx);
    valuesZero.denominatorZero = ext_t::load(input, 2 * height + zeroIdx);
    valuesZero.denominatorOne = ext_t::load(input, 3 * height + zeroIdx);

    // Load one values
    CircuitValues valuesOne;
    if (padding && i == outputHeight - 1) {
        valuesOne = CircuitValues::paddingValues();
    } else {
        valuesOne.numeratorZero = ext_t::load(input, oneIdx);
        valuesOne.numeratorOne = ext_t::load(input, height + oneIdx);
        valuesOne.denominatorZero = ext_t::load(input, 2 * height + oneIdx);
        valuesOne.denominatorOne = ext_t::load(input, 3 * height + oneIdx);
    }

    CircuitValues values = CircuitValues::fix_last_variable(valuesZero, valuesOne, alpha);

    // printf("writing output to i: %ld, threadIdx.x: %ld\n", i, threadIdx.x);
    // Store the restricted values
    ext_t::store(output, i, values.numeratorZero);
    ext_t::store(output, outputHeight + i, values.numeratorOne);
    ext_t::store(output, 2 * outputHeight + i, values.denominatorZero);
    ext_t::store(output, 3 * outputHeight + i, values.denominatorOne);
}

// i is between 0 and height / 2.
__device__ __forceinline__ SumAsPolyResult sumAsPolyInteractionLayerInner(
    ext_t* __restrict__ layer,
    const ext_t* __restrict__ eqPoly,
    const ext_t lambda,
    const size_t height,
    size_t i) {

    bool padding = height & 1;
    // The indices for the values at (i, 0) and (i, 1)
    size_t zeroIdx = i << 1;
    size_t oneIdx = (i << 1) + 1;

    // Load zero values
    CircuitValues valuesZero;
    valuesZero.numeratorZero = ext_t::load(layer, zeroIdx);
    valuesZero.numeratorOne = ext_t::load(layer, height + zeroIdx);
    valuesZero.denominatorZero = ext_t::load(layer, 2 * height + zeroIdx);
    valuesZero.denominatorOne = ext_t::load(layer, 3 * height + zeroIdx);

    // Load one values
    CircuitValues valuesOne;
    if (padding && oneIdx >= height) {
        valuesOne = CircuitValues::paddingValues();
    } else {
        valuesOne.numeratorZero = ext_t::load(layer, oneIdx);
        valuesOne.numeratorOne = ext_t::load(layer, height + oneIdx);
        valuesOne.denominatorZero = ext_t::load(layer, 2 * height + oneIdx);
        valuesOne.denominatorOne = ext_t::load(layer, 3 * height + oneIdx);
    }

    // Compute the values at one half
    CircuitValues valuesHalf;
    valuesHalf.numeratorZero = valuesZero.numeratorZero + valuesOne.numeratorZero;
    valuesHalf.numeratorOne = valuesZero.numeratorOne + valuesOne.numeratorOne;
    valuesHalf.denominatorZero = valuesZero.denominatorZero + valuesOne.denominatorZero;
    valuesHalf.denominatorOne = valuesZero.denominatorOne + valuesOne.denominatorOne;

    // Load the eq value
    ext_t eqValueZero = ext_t::load(eqPoly, zeroIdx);
    ext_t eqValueOne = ext_t::load(eqPoly, oneIdx);
    ext_t eqValueHalf = eqValueZero + eqValueOne;
    // Add the eq value to the running aggregate
    ext_t eqSum = eqValueHalf;

    // Compute the evaluations of the sumcheck polynomial at zero and one half
    // and add to the running aggregate
    ext_t evalZero = valuesZero.sumAsPoly(lambda, eqValueZero);
    ext_t evalHalf = valuesHalf.sumAsPoly(lambda, eqValueHalf);
    return SumAsPolyResult{evalZero, evalHalf, eqSum};
}
