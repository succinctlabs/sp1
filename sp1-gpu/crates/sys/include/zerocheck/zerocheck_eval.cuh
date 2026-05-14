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
    uint32_t height;
    const felt_t* publicValues;
    const ext_t* powersOfAlpha;
    uint32_t constraintIndex;
    ext_t accumulator;
    uint32_t rowIdx;
    unsigned char eval_point;

  public:
    __device__ JaggedConstraintFolder() {}

    __inline__ __device__ K var_f(unsigned char variant, unsigned int idx) {
        switch (variant) {
        case 0:
            return K::zero();
        case 1:
            return K(idx);
        case 2:
#if defined(ABLATION_MODE) && (ABLATION_MODE == 7 || ABLATION_MODE == 8)
            K zeroPrepVal = K::from_ind((idx ^ threadIdx.x));
            K onePrepVal  = K::from_ind((idx ^ threadIdx.x) ^ 1);
#else
            K zeroPrepVal = K::load(data, preprocessed_ptr + idx * height + (rowIdx << 1));
            K onePrepVal = K::load(data, preprocessed_ptr + idx * height + (rowIdx << 1 | 1));
#endif
            K result = zeroPrepVal;
            K multi_diff;
            switch (eval_point) {
                case 0:
                    break;
                case 2:
                    multi_diff = onePrepVal - zeroPrepVal;
                    multi_diff = multi_diff + multi_diff;
                    result += multi_diff;
                    break;
                case 4:
                    multi_diff = onePrepVal - zeroPrepVal;
                    multi_diff = multi_diff + multi_diff;
                    multi_diff = multi_diff + multi_diff;
                    result += multi_diff;
                    break;
                default:
                    assert(0);
                    break;
            }
            return result;
        case 4:
#if defined(ABLATION_MODE) && (ABLATION_MODE == 7 || ABLATION_MODE == 8)
            K zeroMainVal = K::from_ind((idx ^ threadIdx.x));
            K oneMainVal  = K::from_ind((idx ^ threadIdx.x) ^ 1);
#else
            K zeroMainVal = K::load(data, main_ptr + idx * height + (rowIdx << 1));
            K oneMainVal = K::load(data, main_ptr + idx * height + (rowIdx << 1 | 1));
#endif
            result = zeroMainVal;
            switch (eval_point) {
                case 0:
                    break;
                case 2:
                    multi_diff = oneMainVal - zeroMainVal;
                    multi_diff = multi_diff + multi_diff;
                    result += multi_diff;
                    break;
                case 4:
                    multi_diff = oneMainVal - zeroMainVal;
                    multi_diff = multi_diff + multi_diff;
                    multi_diff = multi_diff + multi_diff;
                    result += multi_diff;
                    break;
                default:
                    assert(0);
                    break;
            }
            return result;
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
