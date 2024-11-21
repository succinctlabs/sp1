#pragma once

#include "poseidon2.hpp"
#include "prelude.hpp"

namespace sp1_recursion_core_sys::poseidon2_wide {
using namespace poseidon2;

template <class F>
__SP1_HOSTDEV__ __SP1_INLINE__ void populate_external_round(
    const F* external_rounds_state, F* sbox, size_t r, F* next_state) {}

template <class F>
__SP1_HOSTDEV__ __SP1_INLINE__ void populate_internal_rounds(
    const F* internal_rounds_state, F* internal_rounds_s0, F* sbox,
    F* ret_state) {}

template <class F>
__SP1_HOSTDEV__ void event_to_row(const F* input, F* external_rounds_state,
                                  F* internal_rounds_state,
                                  F* internal_rounds_s0, F* external_sbox,
                                  F* internal_sbox, F* output_state) {
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
