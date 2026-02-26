#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"
#include "zerocheck/zerocheck.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

// see crates/prover-clea/src/zerocheck.rs
template <typename F, typename EF>
__device__ inline EF zerocheckEval(EF a, F b) {
    EF six = EF::two() + EF::two() + EF::two(); // six = 6 using F's two() method
    return a * a * b + a * b * b + six * b * b * b;
}

template <typename F, typename EF>
__global__ void zerocheckFixLastVariableAndSumAsPoly(
    const F* base_input,
    const EF* ext_input,
    EF* __restrict base_output,
    EF* __restrict ext_output,
    EF alpha,
    EF* univariate_result,
    size_t numPolys,
    size_t inputHeight) {
    size_t outputHeight = (inputHeight + 1) >> 1;
    bool padding = inputHeight & 1;
    EF evalZero = EF::zero();
    EF evalTwo = EF::zero();
    EF evalFour = EF::zero();

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<2>(block);

    for (size_t j = blockDim.y * blockIdx.y + threadIdx.y; j < numPolys;
         j += blockDim.y * gridDim.y) {
        for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < outputHeight;
             i += blockDim.x * gridDim.x) {
            size_t startingIdx = j * inputHeight + (i << 1);

            F baseZeroValue = F::load(base_input, startingIdx);
            F baseOneValue;
            if (padding && i >= outputHeight - 1) {
                baseOneValue = F::zero();
            } else {
                baseOneValue = F::load(base_input, startingIdx + 1);
            }
            // Compute value = zeroValue * (1 - alpha) + oneValue * alpha
            EF baseValue = alpha * baseOneValue + (F::one() - alpha) * baseZeroValue;
            EF::store(base_output, j * outputHeight + i, baseValue);

            EF extZeroValue = EF::load(ext_input, startingIdx);
            EF extOneValue;
            if (padding && i >= outputHeight - 1) {
                extOneValue = EF::zero();
            } else {
                extOneValue = EF::load(ext_input, startingIdx + 1);
            }

            // Compute value = zeroValue * (1 - alpha) + oneValue * alpha
            EF extValue = alpha * extOneValue + (EF::one() - alpha) * extZeroValue;
            EF::store(ext_output, j * outputHeight + i, extValue);

            EF prevBaseValue = tile.shfl(baseValue, 0);
            EF prevExtValue = tile.shfl(extValue, 0);

            bool amEven = (tile.thread_rank() & 1) == 0;
            if (amEven) {
                // The even threads sum in evalZero.
                evalZero += zerocheckEval(extValue, baseValue);
            } else {
                EF extSlope = extValue - prevExtValue;
                EF extSlopeTimesTwo = extSlope + extSlope;
                EF extSlopeTimesFour = extSlopeTimesTwo + extSlopeTimesTwo;
                EF extEvalAtTwo = prevExtValue + extSlopeTimesTwo;
                EF extEvalAtFour = prevExtValue + extSlopeTimesFour;

                EF baseSlope = baseValue - prevBaseValue;
                EF baseSlopeTimesTwo = baseSlope + baseSlope;
                EF baseSlopeTimesFour = baseSlopeTimesTwo + baseSlopeTimesTwo;
                EF baseEvalAtTwo = prevBaseValue + baseSlopeTimesTwo;
                EF baseEvalAtFour = prevBaseValue + baseSlopeTimesFour;
                // The odd threads read from the even threads and sum in evalHalf.
                evalTwo += zerocheckEval(extEvalAtTwo, baseEvalAtTwo);
                evalFour += zerocheckEval(extEvalAtFour, baseEvalAtFour);
            }
        }
    }
    // __syncthreads();

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    EF* shared = reinterpret_cast<EF*>(memory);

    auto reduce_tile = cg::tiled_partition<32>(block);
    EF evalZeroblockSum = partialBlockReduce(block, reduce_tile, evalZero, shared);
    EF evalTwoblockSum = partialBlockReduce(block, reduce_tile, evalTwo, shared);
    EF evalFourblockSum = partialBlockReduce(block, reduce_tile, evalFour, shared);

    if (threadIdx.x == 0) {
        EF::store(univariate_result, gridDim.x * blockIdx.y + blockIdx.x, evalZeroblockSum);
        EF::store(
            univariate_result,
            gridDim.x * gridDim.y + gridDim.x * blockIdx.y + blockIdx.x,
            evalTwoblockSum);
        EF::store(
            univariate_result,
            2 * gridDim.x * gridDim.y + gridDim.x * blockIdx.y + blockIdx.x,
            evalFourblockSum);
    }
}

template <typename F, typename EF>
__global__ void zerocheckSumAsPoly(
    EF* __restrict__ result,
    const F* __restrict__ base_mle,
    const EF* __restrict__ ext_mle,
    size_t numVariablesMinusOne,
    size_t numPolys) {
    size_t height = 1 << (numVariablesMinusOne);
    size_t inputHeight = height << 1;
    EF evalZero = EF::zero();
    EF evalTwo = EF::zero();
    EF evalFour = EF::zero();
    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {
        for (size_t j = blockDim.y * blockIdx.y + threadIdx.y; j < numPolys;
             j += blockDim.y * gridDim.y) {
            size_t evenIdx = j * inputHeight + (i << 1);
            size_t oddIdx = evenIdx + 1;
            EF prevExtValue = EF::load(ext_mle, evenIdx);
            EF extValue = EF::load(ext_mle, oddIdx);

            EF extSlope = extValue - prevExtValue;
            EF extSlopeTimesTwo = extSlope + extSlope;
            EF extSlopeTimesFour = extSlopeTimesTwo + extSlopeTimesTwo;
            EF extEvalAtTwo = prevExtValue + extSlopeTimesTwo;
            EF extEvalAtFour = prevExtValue + extSlopeTimesFour;

            F prevBaseValue = F::load(base_mle, evenIdx);
            F baseValue = F::load(base_mle, oddIdx);

            F baseSlope = baseValue - prevBaseValue;
            F baseSlopeTimesTwo = baseSlope + baseSlope;
            F baseSlopeTimesFour = baseSlopeTimesTwo + baseSlopeTimesTwo;
            F baseEvalAtTwo = prevBaseValue + baseSlopeTimesTwo;
            F baseEvalAtFour = prevBaseValue + baseSlopeTimesFour;

            evalZero += zerocheckEval(prevExtValue, prevBaseValue);
            evalTwo += zerocheckEval(extEvalAtTwo, baseEvalAtTwo);
            evalFour += zerocheckEval(extEvalAtFour, baseEvalAtFour);
        }
    }

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    EF* shared = reinterpret_cast<EF*>(memory);

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    EF evalZeroBlockSum = partialBlockReduce(block, tile, evalZero, shared);
    EF evalTwoBlockSum = partialBlockReduce(block, tile, evalTwo, shared);
    EF evalFourBlockSum = partialBlockReduce(block, tile, evalFour, shared);

    if (threadIdx.x == 0) {
        EF::store(result, gridDim.x * blockIdx.y + blockIdx.x, evalZeroBlockSum);
        EF::store(
            result,
            gridDim.x * gridDim.y + gridDim.x * blockIdx.y + blockIdx.x,
            evalTwoBlockSum);
        EF::store(
            result,
            2 * gridDim.x * gridDim.y + gridDim.x * blockIdx.y + blockIdx.x,
            evalFourBlockSum);
    }
}

extern "C" void* zerocheck_sum_as_poly_base_ext_kernel() {
    return (void*)zerocheckSumAsPoly<felt_t, ext_t>;
}

extern "C" void* zerocheck_sum_as_poly_ext_ext_kernel() {
    return (void*)zerocheckSumAsPoly<ext_t, ext_t>;
}

extern "C" void* zerocheck_fix_last_variable_and_sum_as_poly_base_ext_kernel() {
    return (void*)zerocheckFixLastVariableAndSumAsPoly<felt_t, ext_t>;
}

extern "C" void* zerocheck_fix_last_variable_and_sum_as_poly_ext_ext_kernel() {
    return (void*)zerocheckFixLastVariableAndSumAsPoly<ext_t, ext_t>;
}
