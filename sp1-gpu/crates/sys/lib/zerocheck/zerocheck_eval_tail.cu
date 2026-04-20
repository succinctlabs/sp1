#include <type_traits>

#include "zerocheck/jagged_mle.cuh"
#include "zerocheck/zerocheck_eval.cuh"
#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"
#include "tracegen/jagged_tracegen/jagged.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

/// Tail-round constraint evaluation kernel.
///
/// One CUDA block handles one air block, with all 3 eval points fused.
/// Each thread handles one (row, eval_point) pair, executing the full
/// instruction stream serially with thread-local registers. This uses
/// the exact same execution logic as jaggedConstraintPolyEval but with
/// a per-air-block grid mapping instead of the jagged iteration.
///
/// Advantages over the main kernel for small totalLen:
/// - No jagged metadata lookup per element (air block known from blockIdx)
/// - All 3 eval points in one block (3x more threads)
/// - Grid size = num_air_blocks (not clamped to 256)
/// - Reduction is per-block, not across a large grid
template <typename K, size_t MEMORY_SIZE>
__global__ void jaggedConstraintPolyEvalTail(
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
    const ext_t* __restrict__ paddedRowAdjustment,
    const felt_t* __restrict__ publicValues,
    const ext_t* __restrict__ powersOfAlpha,
    const ext_t* __restrict__ batchingPowers,
    const ext_t* __restrict__ powersOfLambda,
    const uint32_t* __restrict__ preprocessed_column,
    const uint32_t* __restrict__ main_column,
    uint32_t total_num_preprocessed_column,
    uint32_t rest_point_dim,
    uint32_t numAirBlocks,
    ext_t* __restrict__ constraintValues  // [NUM_EVAL_POINTS * numAirBlocks]
) {
    K expr_f[MEMORY_SIZE];
    JaggedConstraintFolder<K> folder = JaggedConstraintFolder<K>();

    uint32_t airBlockIdx = blockIdx.x;
    if (airBlockIdx >= numAirBlocks) return;

    // Air block metadata.
    uint32_t startIdx = inputJaggedInfo.startIndices[airBlockIdx];
    uint32_t endIdx = inputJaggedInfo.startIndices[airBlockIdx + 1];
    uint32_t numRows = endIdx - startIdx;

    // Unpack chip info from the first element.
    uint32_t packed_info = inputJaggedInfo.denseData.data[startIdx << 1];
    uint32_t chip_idx = (packed_info >> 1) & 0x7F;
    uint32_t preprocessed_idx = (packed_info >> 8) & 0x3FF;
    uint32_t main_idx = (packed_info >> 18) & 0x3FFF;
    uint32_t num_preprocessed_columns = preprocessed_column[chip_idx];
    uint32_t num_main_columns = main_column[chip_idx];
    uint32_t height = 2 * numRows;
    bool is_first_air_block = ((packed_info & 1) == 1);

    uint32_t constraint_offset = constraintIndices[airBlockIdx];
    uint32_t program_start_idx = evalProgramIndices[airBlockIdx];
    uint32_t program_end_idx = evalProgramIndices[airBlockIdx + 1];
    uint32_t f_constant_offset = evalConstantsFIndices[airBlockIdx];

    // Each thread handles one (row, eval_point) pair.
    // Thread mapping: tid = rowIdx * NUM_EVAL_POINTS + evalPointIdx
    constexpr uint32_t NUM_EVAL_POINTS = 3;
    uint32_t totalWork = numRows * NUM_EVAL_POINTS;

    // Per-eval-point partial sums, accumulated across threads.
    ext_t thread_sums[NUM_EVAL_POINTS] = { ext_t::zero(), ext_t::zero(), ext_t::zero() };

    for (uint32_t tid = threadIdx.x; tid < totalWork; tid += blockDim.x) {
        uint32_t rowIdx = tid / NUM_EVAL_POINTS;
        uint32_t evalPointIdx = tid % NUM_EVAL_POINTS;
        felt_t eval_point = get_input_point(evalPointIdx);

        // Initialize registers.
        for (size_t i = 0; i < MEMORY_SIZE; i++) {
            expr_f[i] = K::zero();
        }

        // Set up folder for this (row, eval_point).
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

        thread_sums[evalPointIdx] += computeRowContribution<K>(
            folder, chip_idx, is_first_air_block, num_main_columns, num_preprocessed_columns,
            rowIdx, rest_point_dim, eval_point,
            batchingPowers, partialLagrange, paddedRowAdjustment,
            geq_thresholds, eq_coefficients, powersOfLambda);
    }

    // Block-level reduction: one sum per eval point.
    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    for (uint32_t ep = 0; ep < NUM_EVAL_POINTS; ep++) {
        ext_t reduced = partialBlockReduce(block, tile, thread_sums[ep], shared);
        if (threadIdx.x == 0) {
            ext_t::store(constraintValues, ep * numAirBlocks + airBlockIdx, reduced);
        }
        __syncthreads();
    }
}

// Export kernel function pointers — same MEMORY_SIZE variants as the original.
extern "C" void* jagged_constraint_poly_eval_tail_32_koala_bear_kernel() {
    return (void*)jaggedConstraintPolyEvalTail<kb31_t, 32>;
}
extern "C" void* jagged_constraint_poly_eval_tail_64_koala_bear_kernel() {
    return (void*)jaggedConstraintPolyEvalTail<kb31_t, 64>;
}
extern "C" void* jagged_constraint_poly_eval_tail_128_koala_bear_kernel() {
    return (void*)jaggedConstraintPolyEvalTail<kb31_t, 128>;
}
extern "C" void* jagged_constraint_poly_eval_tail_256_koala_bear_kernel() {
    return (void*)jaggedConstraintPolyEvalTail<kb31_t, 256>;
}
extern "C" void* jagged_constraint_poly_eval_tail_512_koala_bear_kernel() {
    return (void*)jaggedConstraintPolyEvalTail<kb31_t, 512>;
}
extern "C" void* jagged_constraint_poly_eval_tail_1024_koala_bear_kernel() {
    return (void*)jaggedConstraintPolyEvalTail<kb31_t, 1024>;
}

extern "C" void* jagged_constraint_poly_eval_tail_32_koala_bear_extension_kernel() {
    return (void*)jaggedConstraintPolyEvalTail<ext_t, 32>;
}
extern "C" void* jagged_constraint_poly_eval_tail_64_koala_bear_extension_kernel() {
    return (void*)jaggedConstraintPolyEvalTail<ext_t, 64>;
}
extern "C" void* jagged_constraint_poly_eval_tail_128_koala_bear_extension_kernel() {
    return (void*)jaggedConstraintPolyEvalTail<ext_t, 128>;
}
extern "C" void* jagged_constraint_poly_eval_tail_256_koala_bear_extension_kernel() {
    return (void*)jaggedConstraintPolyEvalTail<ext_t, 256>;
}
extern "C" void* jagged_constraint_poly_eval_tail_512_koala_bear_extension_kernel() {
    return (void*)jaggedConstraintPolyEvalTail<ext_t, 512>;
}
extern "C" void* jagged_constraint_poly_eval_tail_1024_koala_bear_extension_kernel() {
    return (void*)jaggedConstraintPolyEvalTail<ext_t, 1024>;
}
