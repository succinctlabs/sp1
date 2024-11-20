#pragma once

#include "prelude.hpp"

namespace sp1_recursion_core_sys::alu_ext {
template <class F>
__SP1_HOSTDEV__ void event_to_row(const ExtAluEvent<F>& event,
                                  ExtAluValueCols<F>& cols) {
  cols.vals = event;
}

template <class F>
__SP1_HOSTDEV__ void instr_to_row(const ExtAluInstr<F>& instr,
                                  ExtAluAccessCols<F>& access) {
  access.addrs = instr.addrs;
  access.is_add = F(0);
  access.is_sub = F(0);
  access.is_mul = F(0);
  access.is_div = F(0);
  access.mult = instr.mult;

  switch (instr.opcode) {
    case ExtAluOpcode::AddE:
      access.is_add = F(1);
      break;
    case ExtAluOpcode::SubE:
      access.is_sub = F(1);
      break;
    case ExtAluOpcode::MulE:
      access.is_mul = F(1);
      break;
    case ExtAluOpcode::DivE:
      access.is_div = F(1);
      break;
  }
}
}  // namespace sp1_recursion_core_sys::alu_ext
