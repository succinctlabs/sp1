#pragma once

#include "prelude.hpp"

namespace sp1_recursion_core_sys::alu_base {
template <class F>
__SP1_HOSTDEV__ void event_to_row(const BaseAluEvent<F>& event,
                                  BaseAluValueCols<F>& cols) {
  cols.vals = event;
}

template <class F>
__SP1_HOSTDEV__ void instr_to_row(const BaseAluInstr<F>& instr,
                                  BaseAluAccessCols<F>& access) {
  access.addrs = instr.addrs;
  access.is_add = F(0);
  access.is_sub = F(0);
  access.is_mul = F(0);
  access.is_div = F(0);
  access.mult = instr.mult;

  switch (instr.opcode) {
    case BaseAluOpcode::AddF:
      access.is_add = F(1);
      break;
    case BaseAluOpcode::SubF:
      access.is_sub = F(1);
      break;
    case BaseAluOpcode::MulF:
      access.is_mul = F(1);
      break;
    case BaseAluOpcode::DivF:
      access.is_div = F(1);
      break;
  }
}
}  // namespace sp1_recursion_core_sys::alu_base
