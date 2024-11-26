#pragma once

#include "poseidon2.hpp"
#include "prelude.hpp"

namespace sp1_recursion_core_sys::poseidon2_wide {
using namespace constants;
using namespace poseidon2;

template <class F>
__SP1_HOSTDEV__ __SP1_INLINE__ void populate_external_round(
    const F external_rounds_state[WIDTH * NUM_EXTERNAL_ROUNDS],
    F sbox[WIDTH * NUM_EXTERNAL_ROUNDS], size_t r, F next_state[WIDTH]) {
  F round_state[WIDTH];
  if (r == 0) {
    // external_linear_layer_immut
    F temp_round_state[WIDTH];
    for (size_t i = 0; i < WIDTH; i++) {
      temp_round_state[i] = external_rounds_state[r * WIDTH + i];
    }
    external_linear_layer<F>(temp_round_state);
    for (size_t i = 0; i < WIDTH; i++) {
      round_state[i] = temp_round_state[i];
    }
  } else {
    for (size_t i = 0; i < WIDTH; i++) {
      round_state[i] = external_rounds_state[r * WIDTH + i];
    }
  }

  size_t round = r < NUM_EXTERNAL_ROUNDS / 2 ? r : r + NUM_INTERNAL_ROUNDS;
  F add_rc[WIDTH];
  for (size_t i = 0; i < WIDTH; i++) {
    add_rc[i] = round_state[i] + F(F::to_monty(RC_16_30_U32[round][i]));
  }

  F sbox_deg_3[WIDTH];
  F sbox_deg_7[WIDTH];
  for (size_t i = 0; i < WIDTH; i++) {
    sbox_deg_3[i] = add_rc[i] * add_rc[i] * add_rc[i];
    sbox_deg_7[i] = sbox_deg_3[i] * sbox_deg_3[i] * add_rc[i];
  }

  for (size_t i = 0; i < WIDTH; i++) {
    sbox[r * WIDTH + i] = sbox_deg_3[i];
  }

  for (size_t i = 0; i < WIDTH; i++) {
    next_state[i] = sbox_deg_7[i];
  }
  external_linear_layer<F>(next_state);
}

template <class F>
__SP1_HOSTDEV__ __SP1_INLINE__ void populate_internal_rounds(
    const F internal_rounds_state[WIDTH],
    F internal_rounds_s0[NUM_INTERNAL_ROUNDS - 1], F sbox[NUM_INTERNAL_ROUNDS],
    F ret_state[WIDTH]) {
  F state[WIDTH];
  for (size_t i = 0; i < WIDTH; i++) {
    state[i] = internal_rounds_state[i];
  }

  F sbox_deg_3[NUM_INTERNAL_ROUNDS];
  for (size_t r = 0; r < NUM_INTERNAL_ROUNDS; r++) {
    size_t round = r + NUM_EXTERNAL_ROUNDS / 2;
    F add_rc = state[0] + F(F::to_monty(RC_16_30_U32[round][0]));

    sbox_deg_3[r] = add_rc * add_rc * add_rc;
    F sbox_deg_7 = sbox_deg_3[r] * sbox_deg_3[r] * add_rc;

    state[0] = sbox_deg_7;
    internal_linear_layer<F>(state);

    if (r < NUM_INTERNAL_ROUNDS - 1) {
      internal_rounds_s0[r] = state[0];
    }
  }

  for (size_t i = 0; i < WIDTH; i++) {
    ret_state[i] = state[i];
  }

  // Store sbox values if pointer is not null
  for (size_t r = 0; r < NUM_INTERNAL_ROUNDS; r++) {
    sbox[r] = sbox_deg_3[r];
  }
}

template <class F>
__SP1_HOSTDEV__ __SP1_INLINE__ void populate_perm(
    const F input[WIDTH], F external_rounds_state[WIDTH * NUM_EXTERNAL_ROUNDS],
    F internal_rounds_state[WIDTH],
    F internal_rounds_s0[NUM_INTERNAL_ROUNDS - 1],
    F external_sbox[WIDTH * NUM_EXTERNAL_ROUNDS],
    F internal_sbox[NUM_INTERNAL_ROUNDS], F output_state[WIDTH]) {
  for (size_t i = 0; i < WIDTH; i++) {
    external_rounds_state[i] = input[i];
  }

  for (size_t r = 0; r < NUM_EXTERNAL_ROUNDS / 2; r++) {
    F next_state[WIDTH];
    populate_external_round<F>(external_rounds_state, external_sbox, r,
                               next_state);
    if (r == NUM_EXTERNAL_ROUNDS / 2 - 1) {
      for (size_t i = 0; i < WIDTH; i++) {
        internal_rounds_state[i] = next_state[i];
      }
    } else {
      for (size_t i = 0; i < WIDTH; i++) {
        external_rounds_state[(r + 1) * WIDTH + i] = next_state[i];
      }
    }
  }

  F ret_state[WIDTH];
  populate_internal_rounds<F>(internal_rounds_state, internal_rounds_s0,
                              internal_sbox, ret_state);
  size_t row = NUM_EXTERNAL_ROUNDS / 2;
  for (size_t i = 0; i < WIDTH; i++) {
    external_rounds_state[row * WIDTH + i] = ret_state[i];
  }

  for (size_t r = NUM_EXTERNAL_ROUNDS / 2; r < NUM_EXTERNAL_ROUNDS; r++) {
    F next_state[WIDTH];
    populate_external_round<F>(external_rounds_state, external_sbox, r,
                               next_state);
    if (r == NUM_EXTERNAL_ROUNDS - 1) {
      for (size_t i = 0; i < WIDTH; i++) {
        output_state[i] = next_state[i];
      }
    } else {
      for (size_t i = 0; i < WIDTH; i++) {
        external_rounds_state[(r + 1) * WIDTH + i] = next_state[i];
      }
    }
  }
}

template <class F>
__SP1_HOSTDEV__ void event_to_row(const F input[WIDTH], F* input_row,
                                  size_t start, size_t stride,
                                  bool sbox_state) {
  F external_rounds_state[WIDTH * NUM_EXTERNAL_ROUNDS];
  F internal_rounds_state[WIDTH];
  F internal_rounds_s0[NUM_INTERNAL_ROUNDS - 1];
  F output_state[WIDTH];
  F external_sbox[WIDTH * NUM_EXTERNAL_ROUNDS];
  F internal_sbox[NUM_INTERNAL_ROUNDS];

  populate_perm<F>(input, external_rounds_state, internal_rounds_state,
                   internal_rounds_s0, external_sbox, internal_sbox,
                   output_state);

  size_t cursor = 0;
  for (size_t i = 0; i < (WIDTH * NUM_EXTERNAL_ROUNDS); i++) {
    input_row[start + (cursor + i) * stride] = external_rounds_state[i];
  }

  cursor += WIDTH * NUM_EXTERNAL_ROUNDS;
  for (size_t i = 0; i < WIDTH; i++) {
    input_row[start + (cursor + i) * stride] = internal_rounds_state[i];
  }

  cursor += WIDTH;
  for (size_t i = 0; i < (NUM_INTERNAL_ROUNDS - 1); i++) {
    input_row[start + (cursor + i) * stride] = internal_rounds_s0[i];
  }

  cursor += NUM_INTERNAL_ROUNDS - 1;
  for (size_t i = 0; i < WIDTH; i++) {
    input_row[start + (cursor + i) * stride] = output_state[i];
  }

  if (sbox_state) {
    cursor += WIDTH;
    for (size_t i = 0; i < (WIDTH * NUM_EXTERNAL_ROUNDS); i++) {
      input_row[start + (cursor + i) * stride] = external_sbox[i];
    }

    cursor += WIDTH * NUM_EXTERNAL_ROUNDS;
    for (size_t i = 0; i < NUM_INTERNAL_ROUNDS; i++) {
      input_row[start + (cursor + i) * stride] = internal_sbox[i];
    }
  }
}

template <class F>
__SP1_HOSTDEV__ void instr_to_row(const Poseidon2SkinnyInstr<F>& instr,
                                  Poseidon2PreprocessedColsWide<F>& cols) {
  for (size_t i = 0; i < WIDTH; i++) {
    cols.input[i] = instr.addrs.input[i];
    cols.output[i] = MemoryAccessColsChips<F>{.addr = instr.addrs.output[i],
                                              .mult = instr.mults[i]};
  }
  cols.is_real_neg = F::zero() - F::one();
}
}  // namespace sp1_recursion_core_sys::poseidon2_wide
