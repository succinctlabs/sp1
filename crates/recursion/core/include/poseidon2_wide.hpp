#pragma once

#include "poseidon2.hpp"
#include "prelude.hpp"

namespace sp1_recursion_core_sys::poseidon2_wide {
using namespace poseidon2;

template <class F>
__SP1_HOSTDEV__ void event_to_row(const F (&input)[WIDTH],
                                  F (*external_rounds_state)[WIDTH],
                                  F internal_rounds_state[WIDTH],
                                  F internal_rounds_s0[NUM_INTERNAL_ROUNDS - 1],
                                  F external_sbox[WIDTH][NUM_EXTERNAL_ROUNDS],
                                  F internal_sbox[NUM_INTERNAL_ROUNDS],
                                  F output_state[WIDTH]) {
  for (size_t i = 0; i < WIDTH; i++) {
    external_rounds_state[0][i] = input[i];
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
