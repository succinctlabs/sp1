#pragma once

#include "prelude.hpp"

namespace sp1_recursion_core_sys::poseidon2_wide {
template <class T>
__SP1_HOSTDEV__ void event_to_row(const T (&input)[WIDTH],
                                  T (*external_rounds_state)[WIDTH],
                                  T internal_rounds_state[WIDTH],
                                  T internal_rounds_s0[NUM_INTERNAL_ROUNDS - 1],
                                  T external_sbox[WIDTH][NUM_EXTERNAL_ROUNDS],
                                  T internal_sbox[NUM_INTERNAL_ROUNDS],
                                  T output_state[WIDTH]) {
  for (size_t i = 0; i < WIDTH; i++) {
    external_rounds_state[0][i] = input[i];
  }
}

template <class T>
__SP1_HOSTDEV__ void instr_to_row(const Poseidon2SkinnyInstr<T>& instr,
                                  size_t len,
                                  Poseidon2PreprocessedColsWide<T>* cols) {}
}  // namespace sp1_recursion_core_sys::poseidon2_wide
