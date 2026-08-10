#include "logup_gkr/execution.cuh"
#include "logup_gkr/first_layer.cuh"
#include "logup_gkr/tracegen.cuh"
#include "config.cuh"
#include <stdio.h>

struct GkrInput {
    felt_t numerator;
    ext_t denominator;

    __device__ __forceinline__ static GkrInput padding() {
        GkrInput values;
        values.numerator = felt_t::zero();
        values.denominator = ext_t::one();
        return values;
    }
};


__device__ __forceinline__ GkrInput interactionValue(
    size_t index,
    size_t rowIdx,
    Interactions<felt_t> const interactions,
    felt_t* const preprocessed,
    felt_t* const global,
    felt_t* const main,
    ext_t const alphaLocal,
    ext_t* const betasLocal,
    ext_t const alphaGlobal,
    ext_t* const betasGlobal,
    size_t height) {
    // Select the challenge pair by the interaction's scope.
    bool isGlobal = interactions.is_global[index];
    ext_t alpha = isGlobal ? alphaGlobal : alphaLocal;
    ext_t* betas = isGlobal ? betasGlobal : betasLocal;

    // Initialize the denominator and beta powers.
    ext_t denominator = alpha;

    // Add argument index to the denominator.
    denominator += betas[0] * interactions.arg_indices[index];

    // Add the interaction values.
    for (size_t k = interactions.values_ptr[index]; k < interactions.values_ptr[index + 1]; k++) {
        felt_t acc = interactions.values_constants[k];
        for (size_t l = interactions.values_col_weights_ptr[k];
             l < interactions.values_col_weights_ptr[k + 1];
             l++) {
            acc +=
                interactions.values_col_weights[l].get(preprocessed, global, main, rowIdx, height);
        }
        denominator += betas[k - interactions.values_ptr[index] + 1] * acc;
    }

    // Calculate the multiplicity values.
    bool isSend = interactions.is_send[index];
    felt_t mult = interactions.mult_constants[index];

    for (size_t k = interactions.multiplicities_ptr[index];
         k < interactions.multiplicities_ptr[index + 1];
         k++) {
        mult += interactions.mult_col_weights[k].get(preprocessed, global, main, rowIdx, height);
    }

    if (!isSend) {
        mult = felt_t::zero() - mult;
    }

    GkrInput value;
    value.numerator = mult;
    value.denominator = denominator;

    return value;
}

__global__ void populateLastCircuitLayer(
    Interactions<felt_t> interactions,
    const uint32_t* startIndices,
    uint32_t* colIndex,
    felt_t* numeratorValues,
    ext_t* denominatorValues,
    felt_t* const preprocessed,
    felt_t* const global,
    felt_t* const main,
    ext_t alphaLocal,
    ext_t* const betaLocal,
    ext_t alphaGlobal,
    ext_t* const betaGlobal,
    size_t localColOffset,
    size_t globalColOffset,
    size_t traceHeight,
    size_t outputHeight,
    bool is_padding) {

    size_t halfTraceHeight;
    if (traceHeight == 0) {
        halfTraceHeight = 1;
    } else {
        halfTraceHeight = (traceHeight + 1) >> 1;
    }

    size_t numInteractions = interactions.num_interactions;
    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < halfTraceHeight;
         i += blockDim.x * gridDim.x) {
        size_t zeroIdx = i << 1;
        size_t oneIdx = (i << 1) + 1;
        size_t parity = i & 1;

        for (size_t j = blockIdx.y * blockDim.y + threadIdx.y; j < numInteractions;
             j += blockDim.y * gridDim.y) {
            // Columns are numbered by grouped interaction index: the chip's local-scope
            // interactions (packed first) map into the local block at `localColOffset`, and its
            // global-scope interactions map into the global block at `globalColOffset` (which
            // starts at `2^k_local`, above the local tree's padding slots).
            size_t numLocal = interactions.num_local_interactions;
            size_t colIdx = j < numLocal ? localColOffset + j : globalColOffset + (j - numLocal);
            size_t startIdx = startIndices[colIdx] << 1;

            size_t restrictedIndex = startIdx + i;
            if (is_padding) {
                FirstLayerCircuitValues values = FirstLayerCircuitValues::paddingValues();
                values.store(numeratorValues, denominatorValues, restrictedIndex, outputHeight);
                values.store(numeratorValues, denominatorValues, restrictedIndex + 1, outputHeight);
                values.store(numeratorValues, denominatorValues, restrictedIndex + 2, outputHeight);
                values.store(numeratorValues, denominatorValues, restrictedIndex + 3, outputHeight);
                colIndex[(restrictedIndex >> 1) + 1] = colIdx;
            } else {
                GkrInput zeroValue;
                GkrInput oneValue;
                zeroValue = interactionValue(
                    j,
                    zeroIdx,
                    interactions,
                    preprocessed,
                    global,
                    main,
                    alphaLocal,
                    betaLocal,
                    alphaGlobal,
                    betaGlobal,
                    traceHeight);
                oneValue = interactionValue(
                    j,
                    oneIdx,
                    interactions,
                    preprocessed,
                    global,
                    main,
                    alphaLocal,
                    betaLocal,
                    alphaGlobal,
                    betaGlobal,
                    traceHeight);
                FirstLayerCircuitValues values;
                values.numeratorZero = zeroValue.numerator;
                values.numeratorOne = oneValue.numerator;
                values.denominatorZero = zeroValue.denominator;
                values.denominatorOne = oneValue.denominator;
                values.store(numeratorValues, denominatorValues, restrictedIndex, outputHeight);
            }

            // Write the output interaction data and dimension. Do it only once per
            // pair of points.
            if (parity == 0) {
                colIndex[restrictedIndex >> 1] = colIdx;
            }
        }
    }
}

/// Materializes the local tree's padding columns `[firstCol, firstCol + numCols)` (the grouped
/// slots between the local block and `2^k_local`): each is a half-height-2 column of `(0, 1)`
/// padding values, identical to a fully-padded chip's columns. Materializing them keeps dense
/// position equal to grouped column index, which the last-layer conversion to a dense
/// interactions layer indexes `eqInteraction` by.
__global__ void populatePaddingColumns(
    const uint32_t* startIndices,
    uint32_t* colIndex,
    felt_t* numeratorValues,
    ext_t* denominatorValues,
    size_t firstCol,
    size_t numCols,
    size_t outputHeight) {
    for (size_t c = blockIdx.x * blockDim.x + threadIdx.x; c < numCols;
         c += blockDim.x * gridDim.x) {
        size_t colIdx = firstCol + c;
        size_t halfStart = startIndices[colIdx];
        size_t fullStart = halfStart << 1;
        FirstLayerCircuitValues values = FirstLayerCircuitValues::paddingValues();
        values.store(numeratorValues, denominatorValues, fullStart, outputHeight);
        values.store(numeratorValues, denominatorValues, fullStart + 1, outputHeight);
        values.store(numeratorValues, denominatorValues, fullStart + 2, outputHeight);
        values.store(numeratorValues, denominatorValues, fullStart + 3, outputHeight);
        colIndex[halfStart] = colIdx;
        colIndex[halfStart + 1] = colIdx;
    }
}

extern "C" void* logup_gkr_populate_last_circuit_layer() {
    return (void*)populateLastCircuitLayer;
}

extern "C" void* logup_gkr_populate_padding_columns() {
    return (void*)populatePaddingColumns;
}
