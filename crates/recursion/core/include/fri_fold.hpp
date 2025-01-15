#pragma once

#include "prelude.hpp"

namespace sp1_recursion_core_sys::fri_fold {
template <class F>
__SP1_HOSTDEV__ void event_to_row(const FriFoldEvent<F>& event,
                                  FriFoldCols<F>& cols) {
  cols.x = event.base_single.x;
  cols.z = event.ext_single.z;
  cols.alpha = event.ext_single.alpha;

  cols.p_at_z = event.ext_vec.ps_at_z;
  cols.p_at_x = event.ext_vec.mat_opening;
  cols.alpha_pow_input = event.ext_vec.alpha_pow_input;
  cols.ro_input = event.ext_vec.ro_input;

  cols.alpha_pow_output = event.ext_vec.alpha_pow_output;
  cols.ro_output = event.ext_vec.ro_output;
}

template <class F>
__SP1_HOSTDEV__ void instr_to_row(const FriFoldInstrFFI<F>& instr, size_t i,
                                  FriFoldPreprocessedCols<F>& cols) {

  cols.is_real = F::one();
  cols.is_first = F::from_bool(i == 0);

  cols.z_mem.addr = instr.ext_single_addrs->z;
  cols.z_mem.mult = F::zero() - F::from_bool(i == 0);

  cols.x_mem.addr = instr.base_single_addrs->x;
  cols.x_mem.mult = F::zero() - F::from_bool(i == 0);

  cols.alpha_mem.addr = instr.ext_single_addrs->alpha;
  cols.alpha_mem.mult = F::zero() - F::from_bool(i == 0);

  cols.alpha_pow_input_mem.addr = instr.ext_vec_addrs_alpha_pow_input_ptr[i];
  cols.alpha_pow_input_mem.mult = F::zero() - F::one();

  cols.ro_input_mem.addr = instr.ext_vec_addrs_ro_input_ptr[i];
  cols.ro_input_mem.mult = F::zero() - F::one();

  cols.p_at_z_mem.addr = instr.ext_vec_addrs_ps_at_z_ptr[i];
  cols.p_at_z_mem.mult = F::zero() - F::one();

  cols.p_at_x_mem.addr = instr.ext_vec_addrs_mat_opening_ptr[i];
  cols.p_at_x_mem.mult = F::zero() - F::one();

  cols.alpha_pow_output_mem.addr = instr.ext_vec_addrs_alpha_pow_output_ptr[i];
  cols.alpha_pow_output_mem.mult = instr.alpha_pow_mults_ptr[i];

  cols.ro_output_mem.addr = instr.ext_vec_addrs_ro_output_ptr[i];
  cols.ro_output_mem.mult = instr.ro_mults_ptr[i];
}
}  // namespace sp1_recursion_core_sys::fri_fold
