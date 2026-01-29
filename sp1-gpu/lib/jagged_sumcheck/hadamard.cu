/**
 * This is just a playground hadamard sumcheck. For example, some kernels don't work with padding,
 * etc. The hadamard kernels used in the actual Jagged Sumcheck are found in
 * `jagged_sumcheck/jagged_sumcheck.cu`.
 */

#include "sum_and_reduce/reduce.cuh"
#include "config.cuh"
#include "jagged_sumcheck/hadamard.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

template <typename F, typename EF>
__global__ void hadamardSumAsPoly(
    EF* __restrict__ result,
    const F* __restrict__ base_mle,
    const EF* __restrict__ ext_mle,
    size_t numVariablesMinusOne,
    size_t numPolys) {
    size_t height = 1 << (numVariablesMinusOne);
    size_t inputHeight = height << 1;
    EF evalZero = EF::zero();
    EF evalHalf = EF::zero();
    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < height;
         i += blockDim.x * gridDim.x) {
        for (size_t j = blockDim.y * blockIdx.y + threadIdx.y; j < numPolys;
             j += blockDim.y * gridDim.y) {
            size_t evenIdx = j * inputHeight + (i << 1);
            size_t oddIdx = evenIdx + 1;
            F zeroValBase = F::load(base_mle, evenIdx);
            F oneValBase = F::load(base_mle, oddIdx);
            EF zeroValExt = EF::load(ext_mle, evenIdx);
            EF oneValExt = EF::load(ext_mle, oddIdx);

            evalZero += zeroValExt * zeroValBase;
            evalHalf += (zeroValExt + oneValExt) * (zeroValBase + oneValBase);
        }
    }

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    EF* shared = reinterpret_cast<EF*>(memory);

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);
    EF evalZeroblockSum = partialBlockReduce(block, tile, evalZero, shared);
    EF evalHalfblockSum = partialBlockReduce(block, tile, evalHalf, shared);

    if (threadIdx.x == 0) {
        EF::store(result, gridDim.x * blockIdx.y + blockIdx.x, evalZeroblockSum);
        EF::store(
            result,
            gridDim.x * gridDim.y + gridDim.x * blockIdx.y + blockIdx.x,
            evalHalfblockSum);
    }
}

/// Note: this does not correclty handle padding.
template <typename F, typename EF>
__global__ void hadamardFixLastVariableAndSumAsPoly(
    const F* base_input,
    const EF* ext_input,
    EF* __restrict base_output,
    EF* __restrict ext_output,
    EF alpha,
    EF* univariate_result,
    size_t inputHeight) {

    size_t outputHeight = (inputHeight + 1) >> 1;
    bool padding = inputHeight & 1;
    EF evalZero = EF::zero();
    EF evalHalf = EF::zero();

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<2>(block);


    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < outputHeight;
         i += blockDim.x * gridDim.x) {
        size_t startingIdx = i << 1;

        F baseZeroValue = F::load(base_input, startingIdx);
        F baseOneValue;
        if (padding && i >= outputHeight - 1) {
            baseOneValue = F::zero();
        } else {
            baseOneValue = F::load(base_input, startingIdx + 1);
        }
        // Compute value = zeroValue * (1 - alpha) + oneValue * alpha
        EF baseValue = alpha * baseOneValue + (F::one() - alpha) * baseZeroValue;
        EF::store(base_output, i, baseValue);

        EF extZeroValue = EF::load(ext_input, startingIdx);
        EF extOneValue;
        if (padding && i >= outputHeight - 1) {
            extOneValue = EF::zero();
        } else {
            extOneValue = EF::load(ext_input, startingIdx + 1);
        }

        // Compute value = zeroValue * (1 - alpha) + oneValue * alpha
        EF extValue = alpha * extOneValue + (EF::one() - alpha) * extZeroValue;
        EF::store(ext_output, i, extValue);

        EF prevBaseValue = tile.shfl(baseValue, 0);
        EF prevExtValue = tile.shfl(extValue, 0);

        bool amEven = (tile.thread_rank() & 1) == 0;
        if (amEven) {
            // The even threads sum in evalZero.
            evalZero += extValue * baseValue;
        } else {
            // The odd threads read from the even threads and sum in evalHalf.
            evalHalf += (prevExtValue + extValue) * (prevBaseValue + baseValue);
        }
    }


    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    EF* shared = reinterpret_cast<EF*>(memory);

    auto reduce_tile = cg::tiled_partition<32>(block);
    EF evalZeroblockSum = partialBlockReduce(block, reduce_tile, evalZero, shared);
    EF evalHalfblockSum = partialBlockReduce(block, reduce_tile, evalHalf, shared);

    if (threadIdx.x == 0) {
        EF::store(univariate_result, gridDim.x * blockIdx.y + blockIdx.x, evalZeroblockSum);
        EF::store(
            univariate_result,
            gridDim.x * gridDim.y + gridDim.x * blockIdx.y + blockIdx.x,
            evalHalfblockSum);
    }
}

extern "C" void* hadamard_sum_as_poly_base_ext_kernel() {
    return (void*)hadamardSumAsPoly<felt_t, ext_t>;
}

extern "C" void* hadamard_sum_as_poly_ext_ext_kernel() {
    return (void*)hadamardSumAsPoly<ext_t, ext_t>;
}

extern "C" void* hadamard_fix_last_variable_and_sum_as_poly_base_ext_kernel() {
    return (void*)hadamardFixLastVariableAndSumAsPoly<felt_t, ext_t>;
}

extern "C" void* hadamard_fix_last_variable_and_sum_as_poly_ext_ext_kernel() {
    return (void*)hadamardFixLastVariableAndSumAsPoly<ext_t, ext_t>;
}
