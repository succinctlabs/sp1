#pragma once

#include "tracegen/jagged_tracegen/jagged.cuh"

extern "C" void* logup_gkr_circuit_transition();
extern "C" void* logup_gkr_populate_last_circuit_layer();
extern "C" void* logup_gkr_extract_output();

// i is between 0 and length(colIndex). Assumes that length(colIndex) is even.
// This method is only available for DenseData types that support circuit transitions
// (JaggedGkrLayer and JaggedFirstGkrLayer)
template <typename DenseData, typename OutputDenseData>
__forceinline__ __device__ void circuitTransitionTwoPadding(
    JaggedMle<DenseData> const& input,
    JaggedMle<OutputDenseData>& output,
    size_t i) {
    size_t colIdx = input.colIndex[i];
    size_t startIdx = input.startIndices[colIdx];
    size_t interactionHeight = input.startIndices[colIdx + 1] - startIdx;

    size_t rowIdx = i - startIdx;

    size_t zeroIdx = i << 1;
    size_t oneIdx = (i << 1) + 1;
    size_t restrictedIndex = (output.startIndices[colIdx] << 1) + rowIdx;

    input.denseData.circuitTransition(output.denseData, restrictedIndex, zeroIdx, oneIdx);

    // If this row does not have a length that is a multiple of four, the next row will have an
    // odd length. So we need to add some extra padding to the next row.
    size_t remainderModFour = interactionHeight & 3;
    bool isLast = (interactionHeight - 1) == rowIdx;
    if (remainderModFour && isLast) {
        input.denseData.pad(output.denseData, restrictedIndex + 1);
        input.denseData.pad(output.denseData, restrictedIndex + 2);

        // We also need to update the output.colIndex.
        output.colIndex[(restrictedIndex >> 1) + 1] = colIdx;
    }

    if (rowIdx & 1) {
        output.colIndex[restrictedIndex >> 1] = colIdx;
    }
}