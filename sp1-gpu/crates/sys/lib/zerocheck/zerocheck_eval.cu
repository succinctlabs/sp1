#include <type_traits>

#include "zerocheck/jagged_mle.cuh"
#include "zerocheck/zerocheck_eval.cuh"
#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"
#include "tracegen/jagged_tracegen/jagged.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

template <typename K, size_t MEMORY_SIZE>
__global__ void jaggedConstraintPolyEval(
    const uint32_t* __restrict__ constraintIndices,
    const Instruction* evalProgram,
    const uint32_t* __restrict__ evalProgramIndices,
    const kb31_t* evalConstantsF,
    const uint32_t* __restrict__ evalConstantsFIndices,
    const ext_t* evalConstantsEF,
    const uint32_t* __restrict__ evalConstantsEFIndices,
    const JaggedMle<DenseBuffer<K>> inputJaggedMle,
    const JaggedMle<InfoBuffer> inputJaggedInfo,
    const ext_t* __restrict__ partialLagrange,
    const uint32_t* __restrict__ geq_thresholds,
    const ext_t* __restrict__ eq_coefficients,
    uint32_t totalLen,
    const ext_t* __restrict__ paddedRowAdjustment,
    const felt_t* __restrict__ publicValues,
    const ext_t* __restrict__ powersOfAlpha,
    const ext_t* __restrict__ batchingPowers,
    const ext_t* __restrict__ powersOfLambda,
    const uint32_t* __restrict__ preprocessed_column,
    const uint32_t* __restrict__ main_column,
    uint32_t total_num_preprocessed_column,
    ext_t* __restrict__ constraintValues,
    uint32_t rest_point_dim
) {
    K expr_f[MEMORY_SIZE];
    JaggedConstraintFolder<K> folder = JaggedConstraintFolder<K>();

    ext_t thread_sum = ext_t::zero();

    // This kernel assumes that a single block deals with a single `xValueIdx`.
    size_t xValueIdx = blockDim.z * blockIdx.z + threadIdx.z;
    felt_t eval_point = get_input_point(xValueIdx);

    for (size_t idx = blockDim.x * blockIdx.x + threadIdx.x; idx < totalLen; idx += blockDim.x * gridDim.x) {
        uint64_t packed_info = inputJaggedInfo.denseData.data[idx << 1];
        assert(packed_info == inputJaggedInfo.denseData.data[idx << 1 | 1]);

        uint32_t chip_idx = (packed_info >> 1) & 0x7FFF;
        uint32_t preprocessed_idx = (packed_info >> 16) & 0xFFFF;
        uint32_t main_idx = (packed_info >> 32) & 0xFFFFFFFF;
        uint32_t num_preprocessed_columns = preprocessed_column[chip_idx];
        uint32_t num_main_columns = main_column[chip_idx];

        uint32_t airBlockIdx = inputJaggedInfo.colIndex[idx];
        bool is_first_air_block = ((packed_info & 1) == 1);

        uint32_t rowIdx = idx - inputJaggedInfo.startIndices[airBlockIdx];
        uint32_t height = 2 * (inputJaggedInfo.startIndices[airBlockIdx + 1] - inputJaggedInfo.startIndices[airBlockIdx]);

        size_t constraint_offset = constraintIndices[airBlockIdx];
        size_t program_start_idx = evalProgramIndices[airBlockIdx];
        size_t program_end_idx = evalProgramIndices[airBlockIdx + 1];
        size_t f_constant_offset = evalConstantsFIndices[airBlockIdx];

        for (size_t i = 0; i < MEMORY_SIZE; i++) {
            expr_f[i] = K::zero();
        }

        folder.data = inputJaggedMle.denseData.data;
        folder.preprocessed_ptr = inputJaggedMle.startIndices[preprocessed_idx] << 1;
        folder.main_ptr = inputJaggedMle.startIndices[total_num_preprocessed_column + 1 + main_idx] << 1;
        folder.height = height;
        folder.publicValues = publicValues;
        folder.powersOfAlpha = powersOfAlpha;
        folder.constraintIndex = constraint_offset;
        folder.accumulator = ext_t::zero();
        folder.rowIdx = rowIdx;
        folder.eval_point = eval_point;

        executeEvalProgram<K, MEMORY_SIZE>(
            expr_f, folder, evalProgram, program_start_idx, program_end_idx,
            evalConstantsF, f_constant_offset);

        thread_sum += computeRowContribution<K>(
            folder, chip_idx, is_first_air_block, num_main_columns, num_preprocessed_columns,
            rowIdx, rest_point_dim, eval_point,
            batchingPowers, partialLagrange, paddedRowAdjustment,
            geq_thresholds, eq_coefficients, powersOfLambda);
    }

    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);
    ext_t thread_block_sum = partialBlockReduce(block, tile, thread_sum, shared);

    if (threadIdx.x == 0 && threadIdx.y == 0 && threadIdx.z == 0) {
        ext_t::store(constraintValues, xValueIdx * gridDim.x + blockIdx.x, thread_block_sum);
    }
}

extern "C" void* jagged_constraint_poly_eval_32_koala_bear_kernel() {
    return (void*)jaggedConstraintPolyEval<kb31_t, 32>;
}

extern "C" void* jagged_constraint_poly_eval_64_koala_bear_kernel() {
    return (void*)jaggedConstraintPolyEval<kb31_t, 64>;
}

extern "C" void* jagged_constraint_poly_eval_128_koala_bear_kernel() {
    return (void*)jaggedConstraintPolyEval<kb31_t, 128>;
}

extern "C" void* jagged_constraint_poly_eval_256_koala_bear_kernel() {
    return (void*)jaggedConstraintPolyEval<kb31_t, 256>;
}

extern "C" void* jagged_constraint_poly_eval_512_koala_bear_kernel() {
    return (void*)jaggedConstraintPolyEval<kb31_t, 512>;
}

extern "C" void* jagged_constraint_poly_eval_1024_koala_bear_kernel() {
    return (void*)jaggedConstraintPolyEval<kb31_t, 1024>;
}

extern "C" void* jagged_constraint_poly_eval_32_koala_bear_extension_kernel() {
    return (void*)jaggedConstraintPolyEval<ext_t, 32>;
}

extern "C" void* jagged_constraint_poly_eval_64_koala_bear_extension_kernel() {
    return (void*)jaggedConstraintPolyEval<ext_t, 64>;
}

extern "C" void* jagged_constraint_poly_eval_128_koala_bear_extension_kernel() {
    return (void*)jaggedConstraintPolyEval<ext_t, 128>;
}

extern "C" void* jagged_constraint_poly_eval_256_koala_bear_extension_kernel() {
    return (void*)jaggedConstraintPolyEval<ext_t, 256>;
}

extern "C" void* jagged_constraint_poly_eval_512_koala_bear_extension_kernel() {
    return (void*)jaggedConstraintPolyEval<ext_t, 512>;
}

extern "C" void* jagged_constraint_poly_eval_1024_koala_bear_extension_kernel() {
    return (void*)jaggedConstraintPolyEval<ext_t, 1024>;
}
