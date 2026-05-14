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

// Ablation experiments for jaggedConstraintPolyEval. 0 = baseline.
//   1: skip all instruction side effects.
//   2: skip side effects in FAssign opcodes (1..3) only.
//   3: replace loads in FAssign opcodes with K::from_ind(instr.b ^ threadIdx.x).
//   4: skip side effects in field-op opcodes (4..25, 59).
//   5: replace var_f calls in field-op opcodes with K::from_ind(idx ^ threadIdx.x).
//   6: replace all loads (var_f, evalConstantsF, expr_f, powersOfAlpha) in field-op opcodes.
#ifndef ABLATION_MODE
#define ABLATION_MODE 5
#endif

#if (ABLATION_MODE == 1) || (ABLATION_MODE == 2)
#define ABL_SKIP_FASSIGN 1
#else
#define ABL_SKIP_FASSIGN 0
#endif

#if (ABLATION_MODE == 1) || (ABLATION_MODE == 4)
#define ABL_SKIP_FIELDOP 1
#else
#define ABL_SKIP_FIELDOP 0
#endif

#if (ABLATION_MODE == 3)
#define ABL_SYNTH_FASSIGN 1
#else
#define ABL_SYNTH_FASSIGN 0
#endif

#if (ABLATION_MODE == 5) || (ABLATION_MODE == 6)
#define ABL_SYNTH_FIELDOP_VARF 1
#else
#define ABL_SYNTH_FIELDOP_VARF 0
#endif

#if (ABLATION_MODE == 6)
#define ABL_SYNTH_FIELDOP_ALL 1
#else
#define ABL_SYNTH_FIELDOP_ALL 0
#endif

#if ABL_SYNTH_FIELDOP_VARF
#define ABL_VARF(variant, idx) K::from_ind((idx) ^ threadIdx.x)
#else
#define ABL_VARF(variant, idx) folder.var_f((variant), (idx))
#endif

#if ABL_SYNTH_FIELDOP_ALL
#define ABL_CONST_F(off, idx) K::from_ind((idx) ^ threadIdx.x)
#define ABL_EXPR_F(idx)       K::from_ind((idx) ^ threadIdx.x)
#define ABL_POW_ALPHA(idx)    ext_t::from_ind((idx) ^ threadIdx.x)
#else
#define ABL_CONST_F(off, idx) evalConstantsF[(off) + (idx)]
#define ABL_EXPR_F(idx)       expr_f[idx]
#define ABL_POW_ALPHA(idx)    folder.powersOfAlpha[idx]
#endif

__device__ inline unsigned char get_input_point(size_t idx) {
    return (unsigned char)(2 * idx);
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
    unsigned char eval_point = get_input_point(xValueIdx);

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
#if !ABL_SKIP_FASSIGN
#if ABL_SYNTH_FASSIGN
                expr_f[instr.a] = K::from_ind(instr.b ^ threadIdx.x);
#else
                expr_f[instr.a] = evalConstantsF[f_constant_offset + instr.b];
#endif
#endif
                break;
            case 2:
                DEBUG("FAssignV: %d <- (%d, %d)\n", instr.a, instr.b_variant, instr.b);
#if !ABL_SKIP_FASSIGN
#if ABL_SYNTH_FASSIGN
                expr_f[instr.a] = K::from_ind(instr.b ^ threadIdx.x);
#else
                expr_f[instr.a] = folder.var_f(instr.b_variant, instr.b);
#endif
#endif
                break;
            case 3:
                DEBUG("FAssignE: %d <- %d\n", instr.a, instr.b);
#if !ABL_SKIP_FASSIGN
#if ABL_SYNTH_FASSIGN
                expr_f[instr.a] = K::from_ind(instr.b ^ threadIdx.x);
#else
                expr_f[instr.a] = expr_f[instr.b];
#endif
#endif
                break;
            case 4:
                DEBUG("FAddVC: %d <- %d + %d\n", instr.a, instr.b_variant, instr.b);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_VARF(instr.b_variant, instr.b) +
                                    ABL_CONST_F(f_constant_offset, instr.c);
#endif
                break;
            case 5:
                DEBUG(
                    "FAddVV: %d <- (%d, %d) + (%d, %d)\n",
                    instr.a,
                    instr.b_variant,
                    instr.b,
                    instr.c_variant,
                    instr.c);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_VARF(instr.b_variant, instr.b) +
                                    ABL_VARF(instr.c_variant, instr.c);
#endif
                break;
            case 6:
                DEBUG(
                    "FAddVE: %d <- (%d, %d) + %d\n",
                    instr.a,
                    instr.b_variant,
                    instr.b,
                    instr.c);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_VARF(instr.b_variant, instr.b) + ABL_EXPR_F(instr.c);
#endif
                break;

            case 7:
                DEBUG("FAddEC: %d <- %d + %d\n", instr.a, instr.b_variant, instr.b);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_EXPR_F(instr.b) + ABL_CONST_F(f_constant_offset, instr.c);
#endif
                break;
            case 8:
                DEBUG(
                    "FAddEV: %d <- %d + (%d, %d)\n",
                    instr.a,
                    instr.b,
                    instr.c_variant,
                    instr.c);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_EXPR_F(instr.b) + ABL_VARF(instr.c_variant, instr.c);
#endif
                break;
            case 9:
                DEBUG("FAddEE: %d <- %d + %d\n", instr.a, instr.b, instr.c);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_EXPR_F(instr.b) + ABL_EXPR_F(instr.c);
#endif
                break;
            case 10:
                DEBUG("FAddAssignE: %d <- %d\n", instr.a, instr.b);
#if !ABL_SKIP_FIELDOP
#if ABL_SYNTH_FIELDOP_ALL
                expr_f[instr.a] = ABL_EXPR_F(instr.a) + ABL_EXPR_F(instr.b);
#else
                expr_f[instr.a] += expr_f[instr.b];
#endif
#endif
                break;

            case 11:
                DEBUG("FSubVC: %d <- %d - %d\n", instr.a, instr.b_variant, instr.b);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_VARF(instr.b_variant, instr.b) -
                                    ABL_CONST_F(f_constant_offset, instr.c);
#endif
                break;
            case 12:
                DEBUG(
                    "FSubVV: %d <- (%d, %d) - (%d, %d)\n",
                    instr.a,
                    instr.b_variant,
                    instr.b,
                    instr.c_variant,
                    instr.c);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_VARF(instr.b_variant, instr.b) -
                                    ABL_VARF(instr.c_variant, instr.c);
#endif
                break;
            case 13:
                DEBUG(
                    "FSubVE: %d <- (%d, %d) - %d\n",
                    instr.a,
                    instr.b_variant,
                    instr.b,
                    instr.c);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_VARF(instr.b_variant, instr.b) - ABL_EXPR_F(instr.c);
#endif
                break;

            case 14:
                DEBUG("FSubEC: %d <- %d - %d\n", instr.a, instr.b, instr.c);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_EXPR_F(instr.b) - ABL_CONST_F(f_constant_offset, instr.c);
#endif
                break;
            case 15:
                DEBUG(
                    "FSubEV: %d <- %d - (%d, %d)\n",
                    instr.a,
                    instr.b,
                    instr.c_variant,
                    instr.c);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_EXPR_F(instr.b) - ABL_VARF(instr.c_variant, instr.c);
#endif
                break;
            case 16:
                DEBUG("FSubEE: %d <- %d - %d\n", instr.a, instr.b, instr.c);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_EXPR_F(instr.b) - ABL_EXPR_F(instr.c);
#endif
                break;
            case 17:
                DEBUG("FSubAssignE: %d <- %d\n", instr.a, instr.b);
#if !ABL_SKIP_FIELDOP
#if ABL_SYNTH_FIELDOP_ALL
                expr_f[instr.a] = ABL_EXPR_F(instr.a) - ABL_EXPR_F(instr.b);
#else
                expr_f[instr.a] -= expr_f[instr.b];
#endif
#endif
                break;

            case 18:
                DEBUG("FMulVC: %d <- %d * %d\n", instr.a, instr.b_variant, instr.b);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_VARF(instr.b_variant, instr.b) *
                                    ABL_CONST_F(f_constant_offset, instr.c);
#endif
                break;
            case 19:
                DEBUG(
                    "FMulVV: %d <- (%d, %d) * (%d, %d)\n",
                    instr.a,
                    instr.b_variant,
                    instr.b,
                    instr.c_variant,
                    instr.c);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_VARF(instr.b_variant, instr.b) *
                                    ABL_VARF(instr.c_variant, instr.c);
#endif
                break;
            case 20:
                DEBUG(
                    "FMulVE: %d <- (%d, %d) * %d\n",
                    instr.a,
                    instr.b_variant,
                    instr.b,
                    instr.c);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_VARF(instr.b_variant, instr.b) * ABL_EXPR_F(instr.c);
#endif
                break;

            case 21:
                DEBUG("FMulEC: %d <- %d * %d\n", instr.a, instr.b_variant, instr.b);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_EXPR_F(instr.b) * ABL_CONST_F(f_constant_offset, instr.c);
#endif
                break;
            case 22:
                DEBUG(
                    "FMulEV: %d <- %d * (%d, %d)\n",
                    instr.a,
                    instr.b,
                    instr.c_variant,
                    instr.c);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_EXPR_F(instr.b) * ABL_VARF(instr.c_variant, instr.c);
#endif
                break;
            case 23:
                DEBUG("FMulEE: %d <- %d * %d\n", instr.a, instr.b, instr.c);
                DEBUG("FMulEE Input: %d, %d\n", expr_f[instr.b], expr_f[instr.c]);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = ABL_EXPR_F(instr.b) * ABL_EXPR_F(instr.c);
#endif
                DEBUG("FMulEE Output: %d\n", expr_f[instr.a]);
                break;
            case 24:
                DEBUG("FMulAssignE: %d <- %d\n", instr.a, instr.b);
#if !ABL_SKIP_FIELDOP
#if ABL_SYNTH_FIELDOP_ALL
                expr_f[instr.a] = ABL_EXPR_F(instr.a) * ABL_EXPR_F(instr.b);
#else
                expr_f[instr.a] *= expr_f[instr.b];
#endif
#endif
                break;

            case 25:
                DEBUG("FNegE: %d <- -%d\n", instr.a, instr.b);
#if !ABL_SKIP_FIELDOP
                expr_f[instr.a] = -ABL_EXPR_F(instr.b);
#endif
                break;

            case 59:
                DEBUG("FAssertZero: %d\n", instr.a);
#if !ABL_SKIP_FIELDOP
                folder.accumulator +=
                    (ABL_POW_ALPHA(folder.constraintIndex) *
                        ABL_EXPR_F(instr.a));
                folder.constraintIndex++;
#endif
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
