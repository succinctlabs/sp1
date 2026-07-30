// Two-round lookahead kernels for the LogUp GKR sumchecks.
//
// Both kernels iterate over QUADS: four consecutive dense elements 4q .. 4q+3 of a layer,
// i.e. the (X, Y) boolean square of the round-1 variable Y (element parity) and the
// round-2 variable X (pair parity). Column pair-heights are even (element heights are
// multiples of 4 at the leaf and `h.div_ceil(4) * 2` keeps them even all the way down),
// so a quad never straddles a column.

#include "logup_gkr/first_layer.cuh"
#include "logup_gkr/lookahead.cuh"
#include "logup_gkr/round.cuh"
#include "sum_and_reduce/reduce.cuh"
#include "tracegen/jagged_tracegen/jagged.cuh"

#include "config.cuh"

static __device__ __forceinline__ CircuitValues
loadLayerValues(const JaggedGkrLayer& denseData, size_t i) {
    return CircuitValues::load(denseData.layer, i, denseData.height);
}

static __device__ __forceinline__ FirstLayerCircuitValues
loadLayerValues(const JaggedFirstGkrLayer& denseData, size_t i) {
    return FirstLayerCircuitValues::load(
        denseData.numeratorValues,
        denseData.denominatorValues,
        i,
        denseData.height);
}

// Componentwise sum, used for the (unscaled) midpoint evaluations of the multilinear
// factors: values(1/2) * 2 = values(0) + values(1).
template <typename Values>
static __device__ __forceinline__ Values addValues(const Values& a, const Values& b) {
    Values values;
    values.numeratorZero = a.numeratorZero + b.numeratorZero;
    values.numeratorOne = a.numeratorOne + b.numeratorOne;
    values.denominatorZero = a.denominatorZero + b.denominatorZero;
    values.denominatorOne = a.denominatorOne + b.denominatorOne;
    return values;
}

// The composition of two `fix_last_variable` folds on one quad (elements
// baseIdx .. baseIdx+3), without materializing the intermediate layer.
template <typename DenseData>
static __device__ __forceinline__ CircuitValues
doubleFoldQuad(const DenseData& denseData, size_t baseIdx, ext_t alpha1, ext_t alpha2) {
    auto v00 = loadLayerValues(denseData, baseIdx);
    auto v01 = loadLayerValues(denseData, baseIdx + 1);
    auto v10 = loadLayerValues(denseData, baseIdx + 2);
    auto v11 = loadLayerValues(denseData, baseIdx + 3);
    CircuitValues lo = decltype(v00)::fix_last_variable(v00, v01, alpha1);
    CircuitValues hi = decltype(v10)::fix_last_variable(v10, v11, alpha1);
    return CircuitValues::fix_last_variable(lo, hi, alpha2);
}

// One pass over the layer accumulating the two-round polynomial
// h(X, Y) = sum_i eq * (lambda * (n0*d1 + n1*d0) + d0*d1) on the grid {0, 1, 1/2}^2.
// h(1, 1) is deducible from the round claim, so only 8 grid values are accumulated, in
// the order: h(0,0), h(0,1), h(0,1/2), h(1,0), h(1,1/2), h(1/2,0), h(1/2,1), h(1/2,1/2).
// Midpoint accumulators carry the unscaled sums (2^3 per half axis, 2^6 for the center);
// the host descales.
//
// Slots 8 and 9 accumulate the eq mass (eqRow * eqInteraction) of the materialized rows
// restricted to Y = 0 and Y = 1 respectively: the host needs eq[8] + eq[9] for round 1's
// padding correction and their alpha_1-interpolation for round 2's.
template <typename DenseData>
__global__ void logupGkrTwoRoundSumLayer(
    ext_t* __restrict__ result,
    const JaggedMle<DenseData> inputJaggedMle,
    const ext_t* __restrict__ eqRow,
    const ext_t* __restrict__ eqInteraction,
    const ext_t lambda) {

    ext_t acc[10];
#pragma unroll
    for (size_t k = 0; k < 10; k++) {
        acc[k] = ext_t::zero();
    }

    for (size_t q = blockIdx.x * blockDim.x + threadIdx.x;
         q < inputJaggedMle.denseData.height >> 1;
         q += blockDim.x * gridDim.x) {

        size_t pairIdx = q << 1;
        size_t colIdx = inputJaggedMle.colIndex[pairIdx];
        size_t startIdx = inputJaggedMle.startIndices[colIdx];
        size_t quadRow = (pairIdx - startIdx) >> 1;

        ext_t eqInteractionValue = ext_t::load(eqInteraction, colIdx);
        ext_t e00 = ext_t::load(eqRow, quadRow << 2) * eqInteractionValue;
        ext_t e01 = ext_t::load(eqRow, (quadRow << 2) + 1) * eqInteractionValue;
        ext_t e10 = ext_t::load(eqRow, (quadRow << 2) + 2) * eqInteractionValue;
        ext_t e11 = ext_t::load(eqRow, (quadRow << 2) + 3) * eqInteractionValue;

        auto v00 = loadLayerValues(inputJaggedMle.denseData, q << 2);
        auto v01 = loadLayerValues(inputJaggedMle.denseData, (q << 2) + 1);
        auto v10 = loadLayerValues(inputJaggedMle.denseData, (q << 2) + 2);
        auto v11 = loadLayerValues(inputJaggedMle.denseData, (q << 2) + 3);

        acc[0] += v00.sumAsPoly(lambda, e00);
        acc[1] += v01.sumAsPoly(lambda, e01);
        acc[2] += addValues(v00, v01).sumAsPoly(lambda, e00 + e01);
        acc[3] += v10.sumAsPoly(lambda, e10);
        acc[4] += addValues(v10, v11).sumAsPoly(lambda, e10 + e11);
        acc[5] += addValues(v00, v10).sumAsPoly(lambda, e00 + e10);
        acc[6] += addValues(v01, v11).sumAsPoly(lambda, e01 + e11);
        acc[7] += addValues(addValues(v00, v01), addValues(v10, v11))
                      .sumAsPoly(lambda, e00 + e01 + e10 + e11);
        acc[8] += e00 + e10;
        acc[9] += e01 + e11;
    }

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);
#pragma unroll
    for (size_t k = 0; k < 10; k++) {
        ext_t blockSum = partialBlockReduce(block, tile, acc[k], shared);
        if (threadIdx.x == 0) {
            ext_t::store(result, k * gridDim.x + blockIdx.x, blockSum);
        }
    }
}

// Folds the first two challenges in one pass, materializing the next circuit layer at a
// quarter of the input height (the jagged metadata advanced two folds), and accumulates
// the round-3 (evalZero, evalHalf, eqSum) from the doubly-folded values while they are
// still in registers. `eqRow` is the host-twice-folded eq row.
//
// The thread owning the even quad of an output pair folds both quads of the pair, so the
// round-3 sums never read another thread's output; odd-quad threads skip. This
// reproduces exactly the composition of two `fixLastVariableTwoPadding` folds: real
// folds land at output elements [0, quads), and the column's last active thread writes
// the trailing pads (the second fold over the intermediate's pads plus the twice-folded
// metadata's own pads) together with the colIndex entries the tail completes.
template <typename DenseData>
__global__ void logupGkrDoubleFixAndSumLayer(
    ext_t* __restrict__ univariate_result,
    const JaggedMle<DenseData> inputJaggedMle,
    JaggedMle<JaggedGkrLayer> outputJaggedMle,
    ext_t alpha1,
    ext_t alpha2,
    const ext_t* __restrict__ eqRow,
    const ext_t* __restrict__ eqInteraction,
    const ext_t lambda) {

    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();
    ext_t eqSum = ext_t::zero();

    for (size_t q = blockIdx.x * blockDim.x + threadIdx.x;
         q < inputJaggedMle.denseData.height >> 1;
         q += blockDim.x * gridDim.x) {

        size_t pairIdx = q << 1;
        size_t colIdx = inputJaggedMle.colIndex[pairIdx];
        size_t startIdx = inputJaggedMle.startIndices[colIdx];
        size_t interactionHeight = inputJaggedMle.startIndices[colIdx + 1] - startIdx;

        // Fail loudly if the even-pair-height invariant is broken — the quad enumeration
        // would silently mix columns otherwise.
        if (interactionHeight & 1) {
            __trap();
        }

        size_t quadRow = (pairIdx - startIdx) >> 1;
        if (quadRow & 1) {
            continue;
        }

        size_t realQuads = interactionHeight >> 1;
        size_t outStartElems = outputJaggedMle.startIndices[colIdx] << 1;
        size_t restrictedIndex = outStartElems + quadRow;

        CircuitValues valuesZero = doubleFoldQuad(inputJaggedMle.denseData, q << 2, alpha1, alpha2);
        valuesZero.store(
            outputJaggedMle.denseData.layer,
            restrictedIndex,
            outputJaggedMle.denseData.height);

        CircuitValues valuesOne;
        if (quadRow + 1 < realQuads) {
            valuesOne = doubleFoldQuad(inputJaggedMle.denseData, (q + 1) << 2, alpha1, alpha2);
            valuesOne.store(
                outputJaggedMle.denseData.layer,
                restrictedIndex + 1,
                outputJaggedMle.denseData.height);
            outputJaggedMle.colIndex[restrictedIndex >> 1] = colIdx;
        } else {
            // The double fold over the intermediate layer's pads is exactly the padding
            // value; the tail below materializes it.
            valuesOne = CircuitValues::paddingValues();
        }

        // The last active thread of the column writes the zero tail (same rule as
        // `JaggedMle::fixLastTwoVariablesTwoPadding`): the doubly-folded pads in
        // [realQuads, 2 * hp2) and the colIndex entries for every output pair the tail
        // completes.
        if (quadRow + 2 >= realQuads) {
            size_t hp1 = ((interactionHeight + 3) >> 2) << 1;
            size_t hp2 = ((hp1 + 3) >> 2) << 1;
            size_t totalElems = hp2 << 1;
            for (size_t t = realQuads; t < totalElems; t++) {
                inputJaggedMle.denseData.pad(outputJaggedMle.denseData, outStartElems + t);
                if ((outStartElems + t) & 1) {
                    outputJaggedMle.colIndex[(outStartElems + t) >> 1] = colIdx;
                }
            }
        }

        // Round-3 sums from the just-folded output pair. The output element row of
        // `valuesZero` is `quadRow` (even), so the twice-folded eq row is read at
        // (quadRow, quadRow + 1) — the same indices `sumAsPolyCircuitLayerInner` would
        // use on the materialized output.
        ext_t eqInteractionValue = ext_t::load(eqInteraction, colIdx);
        ext_t eqValueZero = ext_t::load(eqRow, quadRow) * eqInteractionValue;
        ext_t eqValueOne = ext_t::load(eqRow, quadRow + 1) * eqInteractionValue;
        ext_t eqValueHalf = eqValueZero + eqValueOne;

        eqSum += eqValueHalf;

        CircuitValues valuesHalf = addValues(valuesZero, valuesOne);
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
        ext_t::store(univariate_result, blockIdx.x, evalZeroblockSum);
        ext_t::store(univariate_result, gridDim.x + blockIdx.x, evalHalfblockSum);
        ext_t::store(univariate_result, 2 * gridDim.x + blockIdx.x, eqSumBlockSum);
    }
}

extern "C" void* logup_gkr_two_round_sum_circuit_layer() {
    return (void*)logupGkrTwoRoundSumLayer<JaggedGkrLayer>;
}

extern "C" void* logup_gkr_two_round_sum_first_layer() {
    return (void*)logupGkrTwoRoundSumLayer<JaggedFirstGkrLayer>;
}

extern "C" void* logup_gkr_double_fix_and_sum_circuit_layer() {
    return (void*)logupGkrDoubleFixAndSumLayer<JaggedGkrLayer>;
}

extern "C" void* logup_gkr_double_fix_and_sum_first_layer() {
    return (void*)logupGkrDoubleFixAndSumLayer<JaggedFirstGkrLayer>;
}
