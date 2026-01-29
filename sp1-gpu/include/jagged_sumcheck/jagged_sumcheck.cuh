#pragma once

#include "config.cuh"
#include <stdio.h>

extern "C" void* jagged_sum_as_poly();
extern "C" void* jagged_fix_and_sum();

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

    // Fixes last variable with no concern for padding, since the inputs are guaranteed to be
    // multiples of 16.
    __forceinline__ __device__ void fixLastVariable(
        Hadamard* output,
        size_t restrictedIdx,
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

        output->p[restrictedIdx] = value_p;
        output->q[restrictedIdx] = value_q;
    }
};
