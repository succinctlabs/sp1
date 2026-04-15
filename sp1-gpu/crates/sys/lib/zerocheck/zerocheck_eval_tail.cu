#include <type_traits>

#include "zerocheck/jagged_mle.cuh"
#include "zerocheck/zerocheck_eval.cuh"
#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"
#include "tracegen/jagged_tracegen/jagged.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

__device__ inline ext_t geq_eval_tail(size_t idx, uint32_t threshold, ext_t eq_coefficient) {
    if (idx < threshold) {
        return ext_t::zero();
    } else if (idx == threshold) {
        return ext_t::one() + eq_coefficient;
    } else {
        return ext_t::one();
    }
}

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
        felt_t eval_point = felt_t::from_canonical_u32(2 * evalPointIdx);

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

        // Execute the instruction stream — identical to the original kernel.
        for (size_t i = program_start_idx; i < program_end_idx; i++) {
            Instruction instr = evalProgram[i];
            switch (instr.opcode) {
            case 0: break;
            case 1:  expr_f[instr.a] = evalConstantsF[f_constant_offset + instr.b]; break;
            case 2:  expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b); break;
            case 3:  expr_f[instr.a] = expr_f[instr.b]; break;
            case 4:  expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) + evalConstantsF[f_constant_offset + instr.c]; break;
            case 5:  expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) + folder.var_f(instr.c_variant, instr.c); break;
            case 6:  expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) + expr_f[instr.c]; break;
            case 7:  expr_f[instr.a] = expr_f[instr.b] + evalConstantsF[f_constant_offset + instr.c]; break;
            case 8:  expr_f[instr.a] = expr_f[instr.b] + folder.var_f(instr.c_variant, instr.c); break;
            case 9:  expr_f[instr.a] = expr_f[instr.b] + expr_f[instr.c]; break;
            case 10: expr_f[instr.a] += expr_f[instr.b]; break;
            case 11: expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) - evalConstantsF[f_constant_offset + instr.c]; break;
            case 12: expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) - folder.var_f(instr.c_variant, instr.c); break;
            case 13: expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) - expr_f[instr.c]; break;
            case 14: expr_f[instr.a] = expr_f[instr.b] - evalConstantsF[f_constant_offset + instr.c]; break;
            case 15: expr_f[instr.a] = expr_f[instr.b] - folder.var_f(instr.c_variant, instr.c); break;
            case 16: expr_f[instr.a] = expr_f[instr.b] - expr_f[instr.c]; break;
            case 17: expr_f[instr.a] -= expr_f[instr.b]; break;
            case 18: expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) * evalConstantsF[f_constant_offset + instr.c]; break;
            case 19: expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) * folder.var_f(instr.c_variant, instr.c); break;
            case 20: expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) * expr_f[instr.c]; break;
            case 21: expr_f[instr.a] = expr_f[instr.b] * evalConstantsF[f_constant_offset + instr.c]; break;
            case 22: expr_f[instr.a] = expr_f[instr.b] * folder.var_f(instr.c_variant, instr.c); break;
            case 23: expr_f[instr.a] = expr_f[instr.b] * expr_f[instr.c]; break;
            case 24: expr_f[instr.a] *= expr_f[instr.b]; break;
            case 25: expr_f[instr.a] = -expr_f[instr.b]; break;
            case 59:
                folder.accumulator += (folder.powersOfAlpha[folder.constraintIndex] * expr_f[instr.a]);
                folder.constraintIndex++;
                break;
            }
        }

        // Post-processing: GKR correction, geq correction, eq multiplication.
        ext_t gkr_correction = ext_t::zero();
        ext_t geq_correction = ext_t::zero();

        if (is_first_air_block) {
            for (size_t i = 0; i < num_main_columns; i++) {
                gkr_correction += batchingPowers[i] * folder.var_f(4, i);
            }
            for (size_t i = 0; i < num_preprocessed_columns; i++) {
                gkr_correction += batchingPowers[num_main_columns + i] * folder.var_f(2, i);
            }
            ext_t zeroVal = geq_eval_tail(rowIdx << 1, geq_thresholds[chip_idx], eq_coefficients[chip_idx]);
            ext_t oneVal = geq_eval_tail(rowIdx << 1 | 1, geq_thresholds[chip_idx], eq_coefficients[chip_idx]);
            geq_correction = (zeroVal + eval_point * (oneVal - zeroVal)) * paddedRowAdjustment[chip_idx];
        }

        if (rowIdx < (1u << rest_point_dim)) {
            ext_t eq = ext_t::load(partialLagrange, rowIdx);
            thread_sums[evalPointIdx] += (folder.accumulator + gkr_correction - geq_correction) * eq * powersOfLambda[chip_idx];
        }
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
