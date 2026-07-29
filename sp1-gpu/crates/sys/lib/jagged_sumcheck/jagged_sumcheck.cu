#include "jagged_sumcheck/jagged_sumcheck.cuh"
#include "sum_and_reduce/reduce.cuh"
#include "tracegen/jagged_tracegen/jagged.cuh"


#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>


// Computes the two-round polynomial h(X, Y) = sum_i p(i, X, Y) * q(i, X, Y) on the grid
// {0, 1, 1/2}^2 in a single pass over the trace, so the host can derive both the first- and
// second-round univariate messages without a second pass. Y is the round-1 (last) variable
// selecting within a dense pair; X is the round-2 variable selecting the pair.
//
// h(1, 1) is deducible from the round claim, so only 8 grid values are accumulated, in the
// order: h(0,0), h(0,1), h(0,1/2), h(1,0), h(1,1/2), h(1/2,0), h(1/2,1), h(1/2,1/2).
// Midpoint accumulators carry the unscaled pair sums: entries 2, 4, 5, 6 hold 4*h and
// entry 7 holds 16*h; the host descales.
__global__ void jaggedTwoRoundSumAsPoly(
    ext_t* evaluations,
    const JaggedMle<JaggedSumcheckData> inputJaggedMle) {

    ext_t acc[8];
#pragma unroll
    for (size_t k = 0; k < 8; k++) {
        acc[k] = ext_t::zero();
    }

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < inputJaggedMle.denseData.height >> 1;
         i += blockDim.x * gridDim.x) {

        // q at the four boolean points: q[x][y] for pair j = 2i + x, element y within the
        // pair. Column lengths are padded to a multiple of 16, so no bounds checks are
        // needed.
        ext_t q[2][2];
#pragma unroll
        for (size_t x = 0; x < 2; x++) {
            size_t j = (i << 1) + x;

            size_t colIdx = inputJaggedMle.colIndex[j];
            size_t startIdx = inputJaggedMle.startIndices[colIdx];
            size_t rowIdx = j - startIdx;

            ext_t eqZCol = ext_t::load(inputJaggedMle.denseData.eqZCol, colIdx);
            q[x][0] = eqZCol * ext_t::load(inputJaggedMle.denseData.eqZRow, rowIdx << 1);
            q[x][1] = eqZCol * ext_t::load(inputJaggedMle.denseData.eqZRow, (rowIdx << 1) + 1);
        }

        // p at the four boolean points: b[x][y] = base[4i + 2x + y].
        felt_t b00 = felt_t::load(inputJaggedMle.denseData.base, i << 2);
        felt_t b01 = felt_t::load(inputJaggedMle.denseData.base, (i << 2) + 1);
        felt_t b10 = felt_t::load(inputJaggedMle.denseData.base, (i << 2) + 2);
        felt_t b11 = felt_t::load(inputJaggedMle.denseData.base, (i << 2) + 3);

        acc[0] += b00 * q[0][0];
        acc[1] += b01 * q[0][1];
        acc[2] += (b00 + b01) * (q[0][0] + q[0][1]);
        acc[3] += b10 * q[1][0];
        acc[4] += (b10 + b11) * (q[1][0] + q[1][1]);
        acc[5] += (b00 + b10) * (q[0][0] + q[1][0]);
        acc[6] += (b01 + b11) * (q[0][1] + q[1][1]);
        acc[7] += (b00 + b01 + b10 + b11) * (q[0][0] + q[0][1] + q[1][0] + q[1][1]);
    }

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);
#pragma unroll
    for (size_t k = 0; k < 8; k++) {
        ext_t blockSum = partialBlockReduce(block, tile, acc[k], shared);
        if (threadIdx.x == 0) {
            ext_t::store(
                evaluations,
                k * gridDim.x * gridDim.y + gridDim.x * blockIdx.y + blockIdx.x,
                blockSum);
        }
    }
}

// Folds the first two sumcheck challenges in one pass, materializing the (p, q) pair at a
// quarter of the dense size (instead of half after one fold), and accumulates the round-3
// univariate evaluations from the folded values while they are still in registers.
__global__ void jaggedDoubleFixAndSum(
    ext_t* evaluations,
    const JaggedMle<JaggedSumcheckData> inputJaggedMle,
    ext_t* output_p,
    ext_t* output_q,
    ext_t alpha1,
    ext_t alpha2) {

    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < inputJaggedMle.denseData.height >> 2;
         i += blockDim.x * gridDim.x) {

        // The values of the doubly-folded (p, q) at (2i, 2i + 1).
        Pair folded[2];
#pragma unroll
        for (size_t t = 0; t < 2; t++) {
            size_t k = (i << 1) + t;

            // The values of the singly-folded (p, q) at (2k, 2k + 1). Column lengths are
            // padded to a multiple of 16, so no bounds or padding checks are needed.
            Pair once[2];
#pragma unroll
            for (size_t u = 0; u < 2; u++) {
                size_t j = (k << 1) + u;

                size_t colIdx = inputJaggedMle.colIndex[j];
                size_t startIdx = inputJaggedMle.startIndices[colIdx];
                size_t rowIdx = j - startIdx;

                once[u] = inputJaggedMle.denseData.fixLastVariableValue(
                    j << 1, colIdx, rowIdx << 1, alpha1);
            }

            folded[t] = Pair{
                alpha2.interpolateLinear(once[1].p, once[0].p),
                alpha2.interpolateLinear(once[1].q, once[0].q)};

            ext_t::store(output_p, k, folded[t].p);
            ext_t::store(output_q, k, folded[t].q);
        }

        evalZero += folded[0].q * folded[0].p;
        evalHalf += (folded[0].q + folded[1].q) * (folded[0].p + folded[1].p);
    }

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);
    ext_t evalZeroblockSum = partialBlockReduce(block, tile, evalZero, shared);
    ext_t evalHalfblockSum = partialBlockReduce(block, tile, evalHalf, shared);

    if (threadIdx.x == 0) {
        ext_t::store(evaluations, gridDim.x * blockIdx.y + blockIdx.x, evalZeroblockSum);
        ext_t::store(
            evaluations,
            gridDim.x * gridDim.y + gridDim.x * blockIdx.y + blockIdx.x,
            evalHalfblockSum);
    }
}

__global__ void paddedHadamardFixAndSum(
    const ext_t* base_input,
    const ext_t* ext_input,
    ext_t* __restrict base_output,
    ext_t* __restrict ext_output,
    ext_t alpha,
    ext_t* univariate_result,
    size_t inputHeight) {

    size_t outputHeight = (inputHeight + 1) >> 1;
    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<2>(block);

    size_t halfOutputHeight = (outputHeight + 1) >> 1;


    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < halfOutputHeight;
         i += blockDim.x * gridDim.x) {
        size_t firstIdx = i << 1;
        size_t secondIdx = (i << 1) + 1;

        // Fix last variable for the actual layer. TODO: this has some padding checks that aren't
        // needed.
        Pair pair1 = fixLastVariableInner(base_input, ext_input, alpha, inputHeight, firstIdx);
        ext_t::store(base_output, firstIdx, pair1.p);
        ext_t::store(ext_output, firstIdx, pair1.q);

        // Todo: instead of checking padding conditions twice here ad in sumAsPoly, we should do it
        // once.
        Pair pair2;
        if (secondIdx < outputHeight) {
            pair2 = fixLastVariableInner(base_input, ext_input, alpha, inputHeight, secondIdx);
        } else {
            pair2 = Pair{ext_t::zero(), ext_t::zero()};
        }

        ext_t::store(base_output, secondIdx, pair2.p);
        ext_t::store(ext_output, secondIdx, pair2.q);

        evalZero += pair1.p * pair1.q;
        evalHalf += (pair1.p + pair2.p) * (pair1.q + pair2.q);
    }

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto reduce_tile = cg::tiled_partition<32>(block);
    ext_t evalZeroblockSum = partialBlockReduce(block, reduce_tile, evalZero, shared);
    ext_t evalHalfblockSum = partialBlockReduce(block, reduce_tile, evalHalf, shared);

    if (threadIdx.x == 0) {
        ext_t::store(univariate_result, gridDim.x * blockIdx.y + blockIdx.x, evalZeroblockSum);
        ext_t::store(
            univariate_result,
            gridDim.x * gridDim.y + gridDim.x * blockIdx.y + blockIdx.x,
            evalHalfblockSum);
    }
}


extern "C" void* jagged_two_round_sum_as_poly() { return (void*)jaggedTwoRoundSumAsPoly; }

extern "C" void* jagged_double_fix_and_sum() { return (void*)jaggedDoubleFixAndSum; }

extern "C" void* padded_hadamard_fix_and_sum() { return (void*)paddedHadamardFixAndSum; }
