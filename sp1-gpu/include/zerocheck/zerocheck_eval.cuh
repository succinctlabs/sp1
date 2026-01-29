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