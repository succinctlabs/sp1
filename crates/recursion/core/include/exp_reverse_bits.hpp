#pragma once

#include "prelude.hpp"

namespace sp1_recursion_core_sys::exp_reverse_bits {
template <class F>
__SP1_HOSTDEV__ void event_to_row(const ExpReverseBitsEventFFI<F>& event,
                                  size_t i, ExpReverseBitsLenCols<F>& cols) {
  cols.x = *event.base;
  cols.current_bit = event.exp_ptr[i];
  cols.multiplier = (event.exp_ptr[i] == F::one()) ? *event.base : F::one();
}

template <class F>
__SP1_HOSTDEV__ void instr_to_row(const ExpReverseBitsInstrFFI<F>& instr,
                                  size_t i, size_t len,
                                  ExpReverseBitsLenPreprocessedCols<F>& cols) {
  cols.is_real = F::one();
  cols.iteration_num = F::from_canonical_u32(i);
  cols.is_first = F::from_bool(i == 0);
  cols.is_last = F::from_bool(i == len - 1);

  cols.x_mem.addr = *instr.base;
  cols.x_mem.mult = F::zero() - F::from_bool(i == 0);

  cols.exponent_mem.addr = instr.exp_ptr[i];
  cols.exponent_mem.mult = F::zero() - F::one();

  cols.result_mem.addr = *instr.result;
  cols.result_mem.mult = *instr.mult * F::from_bool(i == len - 1);
}
}  // namespace sp1_recursion_core_sys::exp_reverse_bits
