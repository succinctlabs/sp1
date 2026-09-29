#pragma once

#include "config.cuh"
#include <stdio.h>

extern "C" void* jagged_two_round_sum_as_poly();
extern "C" void* jagged_two_round_fix_and_sum();
extern "C" void* padded_hadamard_fix_and_two_round_sum();
extern "C" void* padded_hadamard_two_round_fix_and_two_round_sum();

struct Hadamard {
    ext_t* p;
    ext_t* q;
};

__device__ __forceinline__ Pair fixLastVariableInner(
    const ext_t* base_input,
    const ext_t* ext_input,
    ext_t alpha,
    size_t height,
    size_t i) {

    // The indices for the values at (i, 0) and (i, 1)
    size_t zeroIdx = i << 1;
    size_t oneIdx = (i << 1) + 1;

    ext_t oneMinusAlpha = ext_t::one() - alpha;

    ext_t baseZeroValue = ext_t::load(base_input, zeroIdx);
    ext_t baseOneValue;
    if (oneIdx >= height) {
        baseOneValue = ext_t::zero();
    } else {
        baseOneValue = ext_t::load(base_input, oneIdx);
    }
    // Compute value = zeroValue * (1 - alpha) + oneValue * alpha
    ext_t baseValue = alpha * baseOneValue + oneMinusAlpha * baseZeroValue;

    ext_t extZeroValue = ext_t::load(ext_input, zeroIdx);
    ext_t extOneValue;
    if (oneIdx >= height) {
        extOneValue = ext_t::zero();
    } else {
        extOneValue = ext_t::load(ext_input, oneIdx);
    }
    // Compute value = zeroValue * (1 - alpha) + oneValue * alpha
    ext_t extValue = alpha * extOneValue + oneMinusAlpha * extZeroValue;

    // Store the restricted values
    return Pair{baseValue, extValue};
}

__device__ __forceinline__ ext_t loadOrZero(const ext_t* input, size_t i, size_t height) {
    return i < height ? ext_t::load(input, i) : ext_t::zero();
}

__device__ __forceinline__ Pair fixLastTwoVariablesInner(
    const ext_t* base_input,
    const ext_t* ext_input,
    ext_t alpha1,
    ext_t alpha2,
    size_t height,
    size_t i) {

    const size_t base = i << 2;
    ext_t p0 = loadOrZero(base_input, base, height);
    ext_t p1 = loadOrZero(base_input, base + 1, height);
    ext_t p2 = loadOrZero(base_input, base + 2, height);
    ext_t p3 = loadOrZero(base_input, base + 3, height);
    ext_t q0 = loadOrZero(ext_input, base, height);
    ext_t q1 = loadOrZero(ext_input, base + 1, height);
    ext_t q2 = loadOrZero(ext_input, base + 2, height);
    ext_t q3 = loadOrZero(ext_input, base + 3, height);

    ext_t p_lo = alpha1.interpolateLinear(p1, p0);
    ext_t p_hi = alpha1.interpolateLinear(p3, p2);
    ext_t q_lo = alpha1.interpolateLinear(q1, q0);
    ext_t q_hi = alpha1.interpolateLinear(q3, q2);
    return Pair{
        alpha2.interpolateLinear(p_hi, p_lo),
        alpha2.interpolateLinear(q_hi, q_lo)};
}

/// Dense data for the jagged sumcheck.
struct JaggedSumcheckData {
    using OutputDenseData = Hadamard;

  public:
    /// Base values
    felt_t* base;
    /// eq_z_col values
    ext_t* eqZCol;
    /// eq_z_row values
    ext_t* eqZRow;
    /// Half of the length of the base vlaues.
    size_t height;

    // Fixes the last variable with no concern for padding, since the inputs are guaranteed
    // to be multiples of 16, returning the restricted (p, q) values instead of storing them.
    __forceinline__ __device__ Pair fixLastVariableValue(
        size_t baseZeroIdx,
        size_t eqZColIdx,
        size_t eqZRowZeroIdx,
        ext_t alpha) const {

        ext_t eqZCol = ext_t::load(this->eqZCol, eqZColIdx);
        ext_t eqZRowZero = ext_t::load(this->eqZRow, eqZRowZeroIdx);
        ext_t eqZRowOne = ext_t::load(this->eqZRow, eqZRowZeroIdx + 1);

        ext_t jaggedValZero = eqZCol * eqZRowZero;
        ext_t jaggedValOne = eqZCol * eqZRowOne;

        ext_t value_q = alpha.interpolateLinear(jaggedValOne, jaggedValZero);

        // TODO: these loads can technically be vectorized.
        felt_t baseZero = felt_t::load(this->base, baseZeroIdx);
        felt_t baseOne = felt_t::load(this->base, baseZeroIdx + 1);

        ext_t value_p = alpha.interpolateLinear(baseOne, baseZero);

        return Pair{value_p, value_q};
    }
};
