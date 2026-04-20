#pragma once

#include "config.cuh"
#include <stdio.h>

struct Instruction {
    unsigned char opcode;
    unsigned char b_variant;
    unsigned char c_variant;
    unsigned short a;
    unsigned short b;
    unsigned short c;
};

template <typename K>
struct JaggedConstraintFolder {
  public:
    const K* data;
    size_t preprocessed_ptr;
    size_t main_ptr;
    size_t height;
    const felt_t* publicValues;
    const ext_t* powersOfAlpha;
    size_t constraintIndex;
    ext_t accumulator;
    size_t rowIdx;
    felt_t eval_point;

  public:
    __device__ JaggedConstraintFolder() {}

    __inline__ __device__ K var_f(unsigned char variant, unsigned int idx) {
        switch (variant) {
        case 0:
            return K::zero();
        case 1:
            return K(idx);
        case 2:
            K zeroPrepVal = K::load(data, preprocessed_ptr + idx * height + (rowIdx << 1));
            K onePrepVal = K::load(data, preprocessed_ptr + idx * height + (rowIdx << 1 | 1));
            return zeroPrepVal + eval_point * (onePrepVal - zeroPrepVal);
        case 4:
            K zeroMainVal = K::load(data, main_ptr + idx * height + (rowIdx << 1));
            K oneMainVal = K::load(data, main_ptr + idx * height + (rowIdx << 1 | 1));
            return zeroMainVal + eval_point * (oneMainVal - zeroMainVal);
        case 9:
            return K(felt_t::load(publicValues, idx));
        default:
            // Case 3: next row for for preprocessed trace for univariate.
            // Case 5: next row for for main trace for univariate.
            // Case 6: isFirstRow for univariate.
            // Case 7: isLastRow for univariate.
            // Case 8: isTransition for univariate.
            // Case 10: globalCumulativeSum for univariate.
            assert(0);
            return K::zero();
        }
    }

    __inline__ __device__ ext_t var_ef(unsigned char variant, unsigned int idx) {
        switch (variant) {
        case 0:
            return ext_t::zero();
        default:
            // Case 1: Permutation trace row for univariate.
            // Case 2: Permutation trace next row for multivariate.
            // Case 3: Permutation challenge for univariate.
            // Case 4: Local cumulative sum for univariate.
            assert(0);
            return ext_t::zero();
        }
    }
};


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

/// Execute the straight-line instruction stream at `evalProgram[program_start_idx..program_end_idx]`
/// against `expr_f` and `folder`. Shared by the standard and tail kernels.
template <typename K, size_t MEMORY_SIZE>
__device__ __inline__ void executeEvalProgram(
    K (&expr_f)[MEMORY_SIZE],
    JaggedConstraintFolder<K>& folder,
    const Instruction* evalProgram,
    size_t program_start_idx,
    size_t program_end_idx,
    const kb31_t* evalConstantsF,
    size_t f_constant_offset
) {
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
}

/// Compute this (row, eval_point) pair's contribution to the zerocheck sum:
/// accumulator + GKR batching correction - geq correction, weighted by eq and lambda.
/// Returns zero when the row is outside the remaining variable range.
template <typename K>
__device__ __forceinline__ ext_t computeRowContribution(
    JaggedConstraintFolder<K>& folder,
    uint32_t chip_idx,
    bool is_first_air_block,
    uint32_t num_main_columns,
    uint32_t num_preprocessed_columns,
    uint32_t rowIdx,
    uint32_t rest_point_dim,
    felt_t eval_point,
    const ext_t* __restrict__ batchingPowers,
    const ext_t* __restrict__ partialLagrange,
    const ext_t* __restrict__ paddedRowAdjustment,
    const uint32_t* __restrict__ geq_thresholds,
    const ext_t* __restrict__ eq_coefficients,
    const ext_t* __restrict__ powersOfLambda
) {
    ext_t gkr_correction = ext_t::zero();
    ext_t geq_correction = ext_t::zero();

    if (is_first_air_block) {
        for (size_t i = 0; i < num_main_columns; i++) {
            gkr_correction += batchingPowers[i] * folder.var_f(4, i);
        }
        for (size_t i = 0; i < num_preprocessed_columns; i++) {
            gkr_correction += batchingPowers[num_main_columns + i] * folder.var_f(2, i);
        }
        ext_t zeroVal = geq_eval(rowIdx << 1, geq_thresholds[chip_idx], eq_coefficients[chip_idx]);
        ext_t oneVal = geq_eval(rowIdx << 1 | 1, geq_thresholds[chip_idx], eq_coefficients[chip_idx]);
        geq_correction = (zeroVal + eval_point * (oneVal - zeroVal)) * paddedRowAdjustment[chip_idx];
    }

    if (rowIdx < (1u << rest_point_dim)) {
        ext_t eq = ext_t::load(partialLagrange, rowIdx);
        return (folder.accumulator + gkr_correction - geq_correction) * eq * powersOfLambda[chip_idx];
    }
    return ext_t::zero();
}


extern "C" void* jagged_constraint_poly_eval_32_koala_bear_kernel();
extern "C" void* jagged_constraint_poly_eval_64_koala_bear_kernel();
extern "C" void* jagged_constraint_poly_eval_128_koala_bear_kernel();
extern "C" void* jagged_constraint_poly_eval_256_koala_bear_kernel();
extern "C" void* jagged_constraint_poly_eval_512_koala_bear_kernel();
extern "C" void* jagged_constraint_poly_eval_1024_koala_bear_kernel();

extern "C" void* jagged_constraint_poly_eval_32_koala_bear_extension_kernel();
extern "C" void* jagged_constraint_poly_eval_64_koala_bear_extension_kernel();
extern "C" void* jagged_constraint_poly_eval_128_koala_bear_extension_kernel();
extern "C" void* jagged_constraint_poly_eval_256_koala_bear_extension_kernel();
extern "C" void* jagged_constraint_poly_eval_512_koala_bear_extension_kernel();
extern "C" void* jagged_constraint_poly_eval_1024_koala_bear_extension_kernel();