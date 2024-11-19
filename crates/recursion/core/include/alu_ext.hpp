#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::alu_ext {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::ExtAluEvent<F> &event, sp1_recursion_core_sys::ExtAluValueCols<F> &cols) {
  cols.vals = event;
}

template <class F> __SP1_HOSTDEV__ void instr_to_row(
    const sp1_recursion_core_sys::ExtAluInstr<F> &instr,
    sp1_recursion_core_sys::ExtAluAccessCols<F> &access) {
    access.addrs = instr.addrs;
    access.is_add = F(0);
    access.is_sub = F(0);
    access.is_mul = F(0);
    access.is_div = F(0);
    access.mult = instr.mult;

    switch (instr.opcode) {
        case sp1_recursion_core_sys::ExtAluOpcode::AddE:
            access.is_add = F(1);
            break;
        case sp1_recursion_core_sys::ExtAluOpcode::SubE:
            access.is_sub = F(1);
            break;
        case sp1_recursion_core_sys::ExtAluOpcode::MulE:
            access.is_mul = F(1);
            break;
        case sp1_recursion_core_sys::ExtAluOpcode::DivE:
            access.is_div = F(1);
            break;
    }
}

} // namespace recursion::alu_ext
