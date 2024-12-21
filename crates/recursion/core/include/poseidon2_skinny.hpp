#pragma once

#include "poseidon2.hpp"
#include "prelude.hpp"

namespace sp1_recursion_core_sys::poseidon2_skinny {
using namespace constants;
using namespace poseidon2;

template <class F>
__SP1_HOSTDEV__ __SP1_INLINE__ void populate_external_round(
    F round_state[WIDTH], size_t r, F next_state_var[WIDTH]) {
  size_t round =
      (r < NUM_EXTERNAL_ROUNDS / 2) ? r : r + NUM_INTERNAL_ROUNDS - 1;

  for (size_t i = 0; i < WIDTH; i++) {
    F add_rc = round_state[i] + F(F::to_monty(RC_16_30_U32[round][i]));

    F sbox_deg_3 = add_rc * add_rc * add_rc;
    next_state_var[i] = sbox_deg_3 * sbox_deg_3 * add_rc;
  }

  external_linear_layer<F>(next_state_var);
}

template <class F>
__SP1_HOSTDEV__ __SP1_INLINE__ void populate_internal_rounds(
    F state[WIDTH], F internal_rounds_s0[NUM_INTERNAL_ROUNDS_S0],
    F next_state_var[WIDTH]) {
  for (size_t i = 0; i < WIDTH; i++) {
    next_state_var[i] = state[i];
  }

  for (size_t r = 0; r < NUM_INTERNAL_ROUNDS; r++) {
    size_t round = r + NUM_EXTERNAL_ROUNDS / 2;
    F add_rc = next_state_var[0] + F(F::to_monty(RC_16_30_U32[round][0]));

    F sbox_deg_3 = add_rc * add_rc * add_rc;
    F sbox_deg_7 = sbox_deg_3 * sbox_deg_3 * add_rc;

    next_state_var[0] = sbox_deg_7;
    internal_linear_layer<F>(next_state_var);

    if (r < NUM_INTERNAL_ROUNDS - 1) {
      internal_rounds_s0[r] = next_state_var[0];
    }
  }
}

template <class F>
__SP1_HOSTDEV__ void event_to_row(const Poseidon2Event<F>& event,
                                  Poseidon2<F> cols[OUTPUT_ROUND_IDX + 1]) {
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
    } else {
      populate_internal_rounds<F>(col.state_var, col.internal_rounds_s0,
                                  next_row_cols.state_var);
    }
  }
}

template <class F>
__SP1_HOSTDEV__ void instr_to_row(const Poseidon2Instr<F>& instr, size_t i,
                                  Poseidon2PreprocessedColsSkinny<F>& cols) {
  cols.round_counters_preprocessed.is_input_round =
      F::from_bool(i == INPUT_ROUND_IDX);
  bool is_external_round =
      i != INPUT_ROUND_IDX && i != INTERNAL_ROUND_IDX && i != OUTPUT_ROUND_IDX;
  cols.round_counters_preprocessed.is_external_round =
      F::from_bool(is_external_round);
  cols.round_counters_preprocessed.is_internal_round =
      F::from_bool(i == INTERNAL_ROUND_IDX);

  for (size_t j = 0; j < WIDTH; j++) {
    if (is_external_round) {
      size_t r = i - 1;
      size_t round = (i < INTERNAL_ROUND_IDX) ? r : r + NUM_INTERNAL_ROUNDS - 1;
      cols.round_counters_preprocessed.round_constants[j] =
          F(F::to_monty(RC_16_30_U32[round][j]));
    } else if (i == INTERNAL_ROUND_IDX) {
      cols.round_counters_preprocessed.round_constants[j] =
          F(F::to_monty(RC_16_30_U32[NUM_EXTERNAL_ROUNDS / 2 + j][0]));
    } else {
      cols.round_counters_preprocessed.round_constants[j] = F::zero();
    }
  }

  if (i == INPUT_ROUND_IDX) {
    for (size_t j = 0; j < WIDTH; j++) {
      cols.memory_preprocessed[j].addr = instr.addrs.input[j];
      cols.memory_preprocessed[j].mult = F::zero() - F::one();
    }
  } else if (i == OUTPUT_ROUND_IDX) {
    for (size_t j = 0; j < WIDTH; j++) {
      cols.memory_preprocessed[j].addr = instr.addrs.output[j];
      cols.memory_preprocessed[j].mult = instr.mults[j];
    }
  }
}
}  // namespace sp1_recursion_core_sys::poseidon2_skinny
