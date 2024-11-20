#pragma once

#include "prelude.hpp"

namespace sp1_recursion_core_sys::poseidon2_skinny {
constexpr size_t OUTPUT_ROUND_IDX = 10;

constexpr size_t INTERNAL_ROUND_IDX = 5;

template <class F>
__SP1_HOSTDEV__ __SP1_INLINE__ void external_linear_layer(F* state_var) {
  for (size_t j = 0; j < WIDTH; j += 4) {
    F t01 = state_var[j + 0] + state_var[j + 1];
    F t23 = state_var[j + 2] + state_var[j + 3];
    F t0123 = t01 + t23;
    F t01123 = t0123 + state_var[j + 1];
    F t01233 = t0123 + state_var[j + 3];

    // The order here is important. Need to overwrite x[0] and x[2] after x[1] and x[3].
    state_var[j + 3] =
        t01233 +
        (state_var[j + 0] * state_var[j + 0]);  // 3*x[0] + x[1] + x[2] + 2*x[3]
    state_var[j + 1] =
        t01123 +
        (state_var[j + 2] * state_var[j + 2]);  // x[0] + 2*x[1] + 3*x[2] + x[3]
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
__SP1_HOSTDEV__ void populate_external_round(F* round_state, size_t r,
                                             F* next_state_var) {
  size_t round =
      (r < NUM_EXTERNAL_ROUNDS / 2) ? r : r + NUM_INTERNAL_ROUNDS - 1;

  for (size_t i = 0; i < WIDTH; i++) {
    // F add_rc = round_state[i] + F::from_wrapped_u32(RC_16_30_U32[round][i]);

    // F sbox_deg_3 = add_rc * add_rc * add_rc;
    // next_state_var[i] = sbox_deg_3 * sbox_deg_3 * add_rc;
  }

  external_linear_layer(next_state_var);
}

template <class F>
__SP1_HOSTDEV__ void event_to_row(const Poseidon2Event<F>& event, size_t len,
                                  Poseidon2<F>* cols) {
  Poseidon2<F>& first_row = cols[0];
  for (size_t i = 0; i < 16; i++) {
    first_row.state_var[i] = event.input[i];
  }

  Poseidon2<F>& second_row = cols[1];
  for (size_t i = 0; i < 16; i++) {
    second_row.state_var[i] = event.input[i];
  }

  external_linear_layer<F>(second_row.state_var);

  for (size_t i = 1; i < OUTPUT_ROUND_IDX; i++) {
    Poseidon2<F>& col = cols[i];
    Poseidon2<F>& next_row_cols = cols[i + 1];

    if (i != INTERNAL_ROUND_IDX) {
      populate_external_round<F>(col.state_var, i - 1, next_row_cols.state_var);
    }
  }
}

template <class F>
__SP1_HOSTDEV__ void instr_to_row(const Poseidon2Instr<F>& instr, size_t i,
                                  size_t len,
                                  Poseidon2PreprocessedColsSkinny<F>* cols) {}
}  // namespace sp1_recursion_core_sys::poseidon2_skinny
