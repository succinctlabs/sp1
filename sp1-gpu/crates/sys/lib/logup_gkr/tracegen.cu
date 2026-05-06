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
    felt_t* const main,
    ext_t const alpha,
    ext_t* const betas,
    size_t height) {
    // Initialize the denominator and beta powers.
    ext_t denominator = alpha;

    // Add argument index to the denominator.
    ext_t argumentIndex = ext_t(interactions.arg_indices[index]);
    denominator += betas[0] * argumentIndex;

    // Add the interaction values.
    for (size_t k = interactions.values_ptr[index]; k < interactions.values_ptr[index + 1]; k++) {
        ext_t acc = ext_t(interactions.values_constants[k]);
        for (size_t l = interactions.values_col_weights_ptr[k];
             l < interactions.values_col_weights_ptr[k + 1];
             l++) {
            acc +=
                ext_t(interactions.values_col_weights[l].get(preprocessed, main, rowIdx, height));
        }
        denominator += betas[k - interactions.values_ptr[index] + 1] * acc;
    }

    // Calculate the multiplicity values.
    bool isSend = interactions.is_send[index];
    felt_t mult = interactions.mult_constants[index];

    for (size_t k = interactions.multiplicities_ptr[index];
         k < interactions.multiplicities_ptr[index + 1];
         k++) {
        mult += interactions.mult_col_weights[k].get(preprocessed, main, rowIdx, height);
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
    felt_t* const main,
    ext_t alpha,
    ext_t* const beta,
    size_t interactionOffset,
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
            size_t colIdx = j + interactionOffset;
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
                    main,
                    alpha,
                    beta,
                    traceHeight);
                oneValue = interactionValue(
                    j,
                    oneIdx,
                    interactions,
                    preprocessed,
                    main,
                    alpha,
                    beta,
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

extern "C" void* logup_gkr_populate_last_circuit_layer() {
    return (void*)populateLastCircuitLayer;
}

// Fused variant: computes the first GKR layer (Felt numerator + Ext denominator) AND the first
// transition into materialized layer 2 (Ext-only) in a single launch. Each thread processes one
// layer-1 row (= 2 stored elements at i_zero = 2p and i_one = 2p + 1) and combines them in
// registers into a single layer-2 stored element at index p within the column.
//
// For column heights whose row count is not a multiple of 4 the layer-2 column has 2 trailing
// padding stored elements (matching `circuitTransitionTwoPadding`), which the last thread in the
// column writes itself. No cross-column boundary issue can arise for K=1 because layer-1 column
// boundaries always sit on even stored indices.
__global__ void populateFirstAndSecondCircuitLayer(
    Interactions<felt_t> interactions,
    // Layer 1 (first GKR layer) outputs.
    const uint32_t* startIndices_l1,
    uint32_t* colIndex_l1,
    felt_t* numeratorValues_l1,
    ext_t* denominatorValues_l1,
    // Layer 2 (materialized) outputs.
    const uint32_t* startIndices_l2,
    uint32_t* colIndex_l2,
    ext_t* layer_l2,
    // Common args.
    felt_t* const preprocessed,
    felt_t* const main,
    ext_t alpha,
    ext_t* const beta,
    size_t interactionOffset,
    size_t traceHeight,
    size_t outputHeight_l1,
    size_t outputHeight_l2,
    bool is_padding) {

    // Layer-1 row count per column for this chip (matches Rust:
    // `max(real_height, 8).div_ceil(4)`). Drives the iteration count directly; halfTraceHeight is
    // not used because for `is_padding` it would be 1 (yielding pairCount = 0), but we still need
    // to fill the 2-row padding column.
    size_t col_h_l1;
    if (is_padding || traceHeight < 8) {
        col_h_l1 = 2;
    } else {
        col_h_l1 = (traceHeight + 3) >> 2;
    }
    size_t pairCount = col_h_l1;

    size_t numInteractions = interactions.num_interactions;

    for (size_t p = blockIdx.x * blockDim.x + threadIdx.x; p < pairCount;
         p += blockDim.x * gridDim.x) {
        size_t i_zero = p << 1;
        size_t i_one = i_zero + 1;

        for (size_t j = blockIdx.y * blockDim.y + threadIdx.y; j < numInteractions;
             j += blockDim.y * gridDim.y) {
            size_t colIdx = j + interactionOffset;
            size_t startIdx_l1_stored = startIndices_l1[colIdx] << 1;
            size_t restrictedIdx_l1_zero = startIdx_l1_stored + i_zero;
            size_t restrictedIdx_l1_one = startIdx_l1_stored + i_one;

            FirstLayerCircuitValues l1_zero;
            FirstLayerCircuitValues l1_one;

            if (is_padding) {
                l1_zero = FirstLayerCircuitValues::paddingValues();
                l1_one = FirstLayerCircuitValues::paddingValues();
            } else {
                size_t zeroTraceA = i_zero << 1;
                size_t oneTraceA = (i_zero << 1) + 1;
                size_t zeroTraceB = i_one << 1;
                size_t oneTraceB = (i_one << 1) + 1;

                GkrInput zeroA = interactionValue(
                    j, zeroTraceA, interactions, preprocessed, main, alpha, beta, traceHeight);
                GkrInput oneA = interactionValue(
                    j, oneTraceA, interactions, preprocessed, main, alpha, beta, traceHeight);
                GkrInput zeroB = interactionValue(
                    j, zeroTraceB, interactions, preprocessed, main, alpha, beta, traceHeight);
                GkrInput oneB = interactionValue(
                    j, oneTraceB, interactions, preprocessed, main, alpha, beta, traceHeight);

                l1_zero.numeratorZero = zeroA.numerator;
                l1_zero.numeratorOne = oneA.numerator;
                l1_zero.denominatorZero = zeroA.denominator;
                l1_zero.denominatorOne = oneA.denominator;

                l1_one.numeratorZero = zeroB.numerator;
                l1_one.numeratorOne = oneB.numerator;
                l1_one.denominatorZero = zeroB.denominator;
                l1_one.denominatorOne = oneB.denominator;
            }

            // Write layer-1 stored elements.
            l1_zero.store(numeratorValues_l1, denominatorValues_l1, restrictedIdx_l1_zero,
                          outputHeight_l1);
            l1_one.store(numeratorValues_l1, denominatorValues_l1, restrictedIdx_l1_one,
                         outputHeight_l1);
            // Layer-1 colIndex update happens at even i (parity 0), which is i_zero = 2p.
            colIndex_l1[restrictedIdx_l1_zero >> 1] = colIdx;

            // Combine the layer-1 row pair into a single layer-2 stored element.
            CircuitValues l2;
            l2.numeratorZero = l1_zero.numeratorZero * l1_zero.denominatorOne
                             + l1_zero.numeratorOne * l1_zero.denominatorZero;
            l2.denominatorZero = l1_zero.denominatorZero * l1_zero.denominatorOne;
            l2.numeratorOne = l1_one.numeratorZero * l1_one.denominatorOne
                            + l1_one.numeratorOne * l1_one.denominatorZero;
            l2.denominatorOne = l1_one.denominatorZero * l1_one.denominatorOne;

            // Write layer-2 stored element. Within a column there are `column_heights_l1[col]`
            // layer-1 rows; each maps to one layer-2 stored at index p within the column.
            size_t restrictedIdx_l2 = (startIndices_l2[colIdx] << 1) + p;
            l2.store(layer_l2, restrictedIdx_l2, outputHeight_l2);

            // Layer-2 colIndex update mirrors the existing transition: write only when the input
            // row index is odd (so each layer-2 row is written exactly once).
            if (p & 1) {
                colIndex_l2[restrictedIdx_l2 >> 1] = colIdx;
            }

            // Trailing padding for layer-2 when the layer-1 column height is not a multiple of 4.
            // Matches `circuitTransitionTwoPadding`: the last thread in the column writes 2
            // padding stored elements and the corresponding colIndex slot.
            if ((col_h_l1 & 3) != 0 && p == col_h_l1 - 1) {
                CircuitValues paddingValues = CircuitValues::paddingValues();
                paddingValues.store(layer_l2, restrictedIdx_l2 + 1, outputHeight_l2);
                paddingValues.store(layer_l2, restrictedIdx_l2 + 2, outputHeight_l2);
                colIndex_l2[(restrictedIdx_l2 >> 1) + 1] = colIdx;
            }
        }
    }
}

extern "C" void* logup_gkr_populate_first_and_second_circuit_layer() {
    return (void*)populateFirstAndSecondCircuitLayer;
}
