#include <stdint.h>

#include "logup_gkr/execution.cuh"
#include "logup_gkr/round.cuh"

#include "tracegen/jagged_tracegen/jagged.cuh"
#include "config.cuh"

__global__ void logUpCircuitTransition(
    const JaggedMle<JaggedGkrLayer> inputJaggedMle,
    JaggedMle<JaggedGkrLayer> outputJaggedMle) {

    size_t height = inputJaggedMle.denseData.height;

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {
        circuitTransitionTwoPadding(inputJaggedMle, outputJaggedMle, i);
    }
}

__global__ void extractOutput(
    const JaggedMle<JaggedGkrLayer> inputJaggedMle,
    ext_t* __restrict__ numerator,
    ext_t* __restrict__ denominator,
    size_t gridHeight) {

    size_t height = inputJaggedMle.denseData.height;
    uint32_t* colIndex = inputJaggedMle.colIndex;
    uint32_t* startIndices = inputJaggedMle.startIndices;
    ext_t* layer = inputJaggedMle.denseData.layer;

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < gridHeight;
         i += blockDim.x * gridDim.x) {

        CircuitValues values;
        // At this point, every other element is padding. So we need to combine every other pair of
        // points.
        if (i << 1 < height) {

            size_t zeroIdx = i << 2;
            size_t oneIdx = (i << 2) + 1;
            size_t colIdx = colIndex[i];

            CircuitValues valuesZero = CircuitValues::load(layer, zeroIdx, height);
            values.numeratorZero = valuesZero.numeratorZero * valuesZero.denominatorOne +
                                   valuesZero.numeratorOne * valuesZero.denominatorZero;

            values.denominatorZero = valuesZero.denominatorZero * valuesZero.denominatorOne;

            CircuitValues valuesOne = CircuitValues::load(layer, oneIdx, height);
            values.numeratorOne = valuesOne.numeratorZero * valuesOne.denominatorOne +
                                  valuesOne.numeratorOne * valuesOne.denominatorZero;
            values.denominatorOne = valuesOne.denominatorZero * valuesOne.denominatorOne;
        } else {
            values = CircuitValues::paddingValues();
        }

        // Store the values in the output MLEs
        size_t zeroIdx = i << 1;
        size_t oneIdx = (i << 1) + 1;

        ext_t::store(numerator, zeroIdx, values.numeratorZero);
        ext_t::store(numerator, oneIdx, values.numeratorOne);
        ext_t::store(denominator, zeroIdx, values.denominatorZero);
        ext_t::store(denominator, oneIdx, values.denominatorOne);
    }
}

extern "C" void* logup_gkr_circuit_transition() {
    return (void*)logUpCircuitTransition;
}

extern "C" void* logup_gkr_extract_output() { return (void*)extractOutput; }