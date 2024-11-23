#pragma once

#include "poseidon2_constants.hpp"
#include "prelude.hpp"

namespace sp1_recursion_core_sys::poseidon2 {
using namespace constants;

constexpr size_t OUTPUT_ROUND_IDX = NUM_EXTERNAL_ROUNDS + 2;
constexpr size_t INPUT_ROUND_IDX = 0;
constexpr size_t INTERNAL_ROUND_IDX = NUM_EXTERNAL_ROUNDS / 2 + 1;

template <class F>
__SP1_HOSTDEV__ __SP1_INLINE__ void external_linear_layer(F state_var[WIDTH]) {
  for (size_t j = 0; j < WIDTH; j += 4) {
    F t01 = state_var[j + 0] + state_var[j + 1];
    F t23 = state_var[j + 2] + state_var[j + 3];
    F t0123 = t01 + t23;
    F t01123 = t0123 + state_var[j + 1];
    F t01233 = t0123 + state_var[j + 3];

    // The order here is important. Need to overwrite x[0] and x[2] after x[1] and x[3].
    state_var[j + 3] =
        t01233 +
        (state_var[j + 0] + state_var[j + 0]);  // 3*x[0] + x[1] + x[2] + 2*x[3]
    state_var[j + 1] =
        t01123 +
        (state_var[j + 2] + state_var[j + 2]);  // x[0] + 2*x[1] + 3*x[2] + x[3]
    state_var[j + 0] = t01123 + t01;            // 2*x[0] + 3*x[1] + x[2] + x[3]
    state_var[j + 2] = t01233 + t23;            // x[0] + x[1] + 2*x[2] + 3*x[3]
  }

  F sums[4] = {F::zero(), F::zero(), F::zero(), F::zero()};
  for (size_t k = 0; k < 4; k++) {
    for (size_t j = 0; j < WIDTH; j += 4) {
      sums[k] = sums[k] + state_var[j + k];
    }
  }

  for (size_t j = 0; j < WIDTH; j++) {
    state_var[j] = state_var[j] + sums[j % 4];
  }
}

template <class F>
__SP1_HOSTDEV__ __SP1_INLINE__ void internal_linear_layer(F state[WIDTH]) {
  F matmul_constants[WIDTH];
  for (size_t i = 0; i < WIDTH; i++) {
    matmul_constants[i] = F(F::to_monty(F::from_monty(
        constants::POSEIDON2_INTERNAL_MATRIX_DIAG_16_BABYBEAR_MONTY[i].val)));
  }

  F sum = F::zero();
  for (size_t i = 0; i < WIDTH; i++) {
    sum = sum + state[i];
  }

  for (size_t i = 0; i < WIDTH; i++) {
    state[i] = state[i] * matmul_constants[i];
    state[i] = state[i] + sum;
  }

  F monty_inverse = F(F::to_monty(F::from_monty(1)));
  for (size_t i = 0; i < WIDTH; i++) {
    state[i] = state[i] * monty_inverse;
  }
}
}  // namespace sp1_recursion_core_sys::poseidon2