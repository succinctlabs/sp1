#include <type_traits>

#include "zerocheck/jagged_mle.cuh"
#include "zerocheck/zerocheck_eval.cuh"
#include "config.cuh"
#include "sum_and_reduce/reduce.cuh"
#include "tracegen/jagged_tracegen/jagged.cuh"

#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

namespace cg = cooperative_groups;

#define DEBUG_FLAG 0 // Set this to 0 or 1

#if DEBUG_FLAG == 1
#define DEBUG(...) printf(__VA_ARGS__)
#else
#define DEBUG(...) // Do nothing
#endif

__device__ inline felt_t get_input_point(size_t idx) {
    return felt_t::from_canonical_u32(2 * idx);
}

__device__ inline ext_t geq_eval(size_t idx, uint32_t threshold, ext_t eq_coefficient) {
    if (idx < threshold) {
        return ext_t::zero();
    } else if (idx == threshold) {
        return ext_t::one() + eq_coefficient;
    } else {
        return ext_t::one();
    }
}

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
        uint32_t packed_info = inputJaggedInfo.denseData.data[idx << 1];
        assert(packed_info == inputJaggedInfo.denseData.data[idx << 1 | 1]);

        uint32_t chip_idx = (packed_info >> 1) & 0x7F;
        uint32_t preprocessed_idx = (packed_info >> 8) & 0x3FF;
        uint32_t main_idx = (packed_info >> 18) & 0x3FFF;
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
        size_t ef_constant_offset = evalConstantsEFIndices[airBlockIdx];
        
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

        for (size_t i = program_start_idx; i < program_end_idx; i++) {
            Instruction instr = evalProgram[i];
            switch (instr.opcode) {
            case 0:
                DEBUG("EMPTY\n");
                break;

            case 1:
                DEBUG("FAssignC: %d <- %d\n", instr.a, instr.b);
                expr_f[instr.a] = evalConstantsF[f_constant_offset + instr.b];
                break;
            case 2:
                DEBUG("FAssignV: %d <- (%d, %d)\n", instr.a, instr.b_variant, instr.b);
                expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b);
                break;
            case 3:
                DEBUG("FAssignE: %d <- %d\n", instr.a, instr.b);
                expr_f[instr.a] = expr_f[instr.b];
                break;
            case 4:
                DEBUG("FAddVC: %d <- %d + %d\n", instr.a, instr.b_variant, instr.b);
                expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) +
                                    evalConstantsF[f_constant_offset + instr.c];
                break;
            case 5:
                DEBUG(
                    "FAddVV: %d <- (%d, %d) + (%d, %d)\n",
                    instr.a,
                    instr.b_variant,
                    instr.b,
                    instr.c_variant,
                    instr.c);
                expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) +
                                    folder.var_f(instr.c_variant, instr.c);
                break;
            case 6:
                DEBUG(
                    "FAddVE: %d <- (%d, %d) + %d\n",
                    instr.a,
                    instr.b_variant,
                    instr.b,
                    instr.c);
                expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) + expr_f[instr.c];
                break;

            case 7:
                DEBUG("FAddEC: %d <- %d + %d\n", instr.a, instr.b_variant, instr.b);
                expr_f[instr.a] = expr_f[instr.b] + evalConstantsF[f_constant_offset + instr.c];
                break;
            case 8:
                DEBUG(
                    "FAddEV: %d <- %d + (%d, %d)\n",
                    instr.a,
                    instr.b,
                    instr.c_variant,
                    instr.c);
                expr_f[instr.a] = expr_f[instr.b] + folder.var_f(instr.c_variant, instr.c);
                break;
            case 9:
                DEBUG("FAddEE: %d <- %d + %d\n", instr.a, instr.b, instr.c);
                expr_f[instr.a] = expr_f[instr.b] + expr_f[instr.c];
                break;
            case 10:
                DEBUG("FAddAssignE: %d <- %d\n", instr.a, instr.b);
                expr_f[instr.a] += expr_f[instr.b];
                break;

            case 11:
                DEBUG("FSubVC: %d <- %d - %d\n", instr.a, instr.b_variant, instr.b);
                expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) -
                                    evalConstantsF[f_constant_offset + instr.c];
                break;
            case 12:
                DEBUG(
                    "FSubVV: %d <- (%d, %d) - (%d, %d)\n",
                    instr.a,
                    instr.b_variant,
                    instr.b,
                    instr.c_variant,
                    instr.c);
                expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) -
                                    folder.var_f(instr.c_variant, instr.c);
                break;
            case 13:
                DEBUG(
                    "FSubVE: %d <- (%d, %d) - %d\n",
                    instr.a,
                    instr.b_variant,
                    instr.b,
                    instr.c);
                expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) - expr_f[instr.c];
                break;

            case 14:
                DEBUG("FSubEC: %d <- %d - %d\n", instr.a, instr.b, instr.c);
                expr_f[instr.a] = expr_f[instr.b] - evalConstantsF[f_constant_offset + instr.c];
                break;
            case 15:
                DEBUG(
                    "FSubEV: %d <- %d - (%d, %d)\n",
                    instr.a,
                    instr.b,
                    instr.c_variant,
                    instr.c);
                expr_f[instr.a] = expr_f[instr.b] - folder.var_f(instr.c_variant, instr.c);
                break;
            case 16:
                DEBUG("FSubEE: %d <- %d - %d\n", instr.a, instr.b, instr.c);
                expr_f[instr.a] = expr_f[instr.b] - expr_f[instr.c];
                break;
            case 17:
                DEBUG("FSubAssignE: %d <- %d\n", instr.a, instr.b);
                expr_f[instr.a] -= expr_f[instr.b];
                break;

            case 18:
                DEBUG("FMulVC: %d <- %d * %d\n", instr.a, instr.b_variant, instr.b);
                expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) *
                                    evalConstantsF[f_constant_offset + instr.c];
                break;
            case 19:
                DEBUG(
                    "FMulVV: %d <- (%d, %d) * (%d, %d)\n",
                    instr.a,
                    instr.b_variant,
                    instr.b,
                    instr.c_variant,
                    instr.c);
                expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) *
                                    folder.var_f(instr.c_variant, instr.c);
                break;
            case 20:
                DEBUG(
                    "FMulVE: %d <- (%d, %d) * %d\n",
                    instr.a,
                    instr.b_variant,
                    instr.b,
                    instr.c);
                expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b) * expr_f[instr.c];
                break;

            case 21:
                DEBUG("FMulEC: %d <- %d * %d\n", instr.a, instr.b_variant, instr.b);
                expr_f[instr.a] = expr_f[instr.b] * evalConstantsF[f_constant_offset + instr.c];
                break;
            case 22:
                DEBUG(
                    "FMulEV: %d <- %d * (%d, %d)\n",
                    instr.a,
                    instr.b,
                    instr.c_variant,
                    instr.c);
                expr_f[instr.a] = expr_f[instr.b] * folder.var_f(instr.c_variant, instr.c);
                break;
            case 23:
                DEBUG("FMulEE: %d <- %d * %d\n", instr.a, instr.b, instr.c);
                DEBUG("FMulEE Input: %d, %d\n", expr_f[instr.b], expr_f[instr.c]);
                expr_f[instr.a] = expr_f[instr.b] * expr_f[instr.c];
                DEBUG("FMulEE Output: %d\n", expr_f[instr.a]);
                break;
            case 24:
                DEBUG("FMulAssignE: %d <- %d\n", instr.a, instr.b);
                expr_f[instr.a] *= expr_f[instr.b];
                break;

            case 25:
                DEBUG("FNegE: %d <- -%d\n", instr.a, instr.b);
                expr_f[instr.a] = -expr_f[instr.b];
                break;

            case 59:
                DEBUG("FAssertZero: %d\n", instr.a);
                folder.accumulator +=
                    (folder.powersOfAlpha[folder.constraintIndex] *
                        expr_f[instr.a]);
                folder.constraintIndex++;
                break;
            }
        }

        ext_t gkr_correction = ext_t::zero();
        ext_t geq_correction = ext_t::zero();

        if (is_first_air_block) {
            for (size_t i = 0; i < num_main_columns; i++) {
                gkr_correction += batchingPowers[i] * folder.var_f(4, i);
            }
            for (size_t i = 0; i < num_preprocessed_columns ; i++) {
                gkr_correction += batchingPowers[num_main_columns + i] * folder.var_f(2, i);
            }
            ext_t zeroVal = geq_eval(rowIdx << 1, geq_thresholds[chip_idx], eq_coefficients[chip_idx]);
            ext_t oneVal = geq_eval(rowIdx << 1 | 1, geq_thresholds[chip_idx], eq_coefficients[chip_idx]);
            geq_correction = (zeroVal + eval_point * (oneVal - zeroVal)) * paddedRowAdjustment[chip_idx];
        }

        if (rowIdx < (1 << rest_point_dim)) {
            ext_t eq = ext_t::load(partialLagrange, rowIdx);
            thread_sum += (folder.accumulator + gkr_correction - geq_correction) * eq * powersOfLambda[chip_idx];
        }
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