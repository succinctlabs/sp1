#pragma once

#include "prelude.hpp"

namespace sp1_recursion_core_sys::batch_fri {
template <class F>
__SP1_HOSTDEV__ void event_to_row(const BatchFRIEvent<F>& event,
                                  BatchFRICols<F>& cols) {
  cols.acc = event.ext_single.acc;
  cols.alpha_pow = event.ext_vec.alpha_pow;
  cols.p_at_z = event.ext_vec.p_at_z;
  cols.p_at_x = event.base_vec.p_at_x;
}

template <class F>
__SP1_HOSTDEV__ void instr_to_row(const BatchFRIInstrFFI<F>& instr,
                                  BatchFRIPreprocessedCols<F>& cols,
                                  size_t index) {
  cols.is_real = F(1);
  cols.is_end = F(index == instr.ext_vec_addrs_p_at_z_len - 1);
  cols.acc_addr = instr.ext_single_addrs->acc;
  cols.alpha_pow_addr = instr.ext_vec_addrs_alpha_pow_ptr[index];
  cols.p_at_z_addr = instr.ext_vec_addrs_p_at_z_ptr[index];
  cols.p_at_x_addr = instr.base_vec_addrs_p_at_x_ptr[index];
}
}  // namespace sp1_recursion_core_sys::batch_fri
