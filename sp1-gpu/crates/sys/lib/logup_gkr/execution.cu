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

/// Combines one interaction-dimension level into the next, tree-combining the `2 * half`
/// per-interaction fractions (`numerator`/`denominator`) into `half` parent fractions while
/// materializing the child pairs into a dense `[4, half]` interaction layer (used by the
/// standalone interaction-combining GKR rounds).
///
/// For each parent `j` (low bit is the last variable, matching `extractOutput`'s interleaving and
/// the verifier's `add_dimension_back` convention):
///   n0 = numerator[2j], n1 = numerator[2j+1], d0 = denominator[2j], d1 = denominator[2j+1]
///   layer = [n0 || n1 || d0 || d1]           (each block `half` long)
///   nextNumerator[j]   = n0 * d1 + n1 * d0
///   nextDenominator[j] = d0 * d1
__global__ void buildInteractionLayer(
    const ext_t* __restrict__ numerator,
    const ext_t* __restrict__ denominator,
    ext_t* __restrict__ layerOut,
    ext_t* __restrict__ nextNumerator,
    ext_t* __restrict__ nextDenominator,
    size_t half) {

    for (size_t j = blockIdx.x * blockDim.x + threadIdx.x; j < half;
         j += blockDim.x * gridDim.x) {
        ext_t n0 = ext_t::load(numerator, j << 1);
        ext_t n1 = ext_t::load(numerator, (j << 1) + 1);
        ext_t d0 = ext_t::load(denominator, j << 1);
        ext_t d1 = ext_t::load(denominator, (j << 1) + 1);

        ext_t::store(layerOut, j, n0);
        ext_t::store(layerOut, half + j, n1);
        ext_t::store(layerOut, 2 * half + j, d0);
        ext_t::store(layerOut, 3 * half + j, d1);

        ext_t::store(nextNumerator, j, n0 * d1 + n1 * d0);
        ext_t::store(nextDenominator, j, d0 * d1);
    }
}

extern "C" void* logup_gkr_circuit_transition() {
    return (void*)logUpCircuitTransition;
}

extern "C" void* logup_gkr_extract_output() { return (void*)extractOutput; }

extern "C" void* logup_gkr_build_interaction_layer() { return (void*)buildInteractionLayer; }