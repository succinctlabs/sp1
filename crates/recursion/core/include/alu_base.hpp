#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::alu_base {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::BaseAluIo<F> &io, sp1_recursion_core_sys::BaseAluValueCols<F> &cols) {
  cols.vals = io;
}

template <class F> __SP1_HOSTDEV__ void instr_to_row(
    const sp1_recursion_core_sys::BaseAluInstr<F> &instr,
    sp1_recursion_core_sys::BaseAluAccessCols<F> &access) {
    access.addrs = instr.addrs;
    access.is_add = F(0);
    access.is_sub = F(0);
    access.is_mul = F(0);
    access.is_div = F(0);
    access.mult = instr.mult;

    // Set the appropriate flag based on opcode
    switch (instr.opcode) {
        case sp1_recursion_core_sys::BaseAluOpcode::AddF:
            access.is_add = F(1);
            break;
        case sp1_recursion_core_sys::BaseAluOpcode::SubF:
            access.is_sub = F(1);
            break;
        case sp1_recursion_core_sys::BaseAluOpcode::MulF:
            access.is_mul = F(1);
            break;
        case sp1_recursion_core_sys::BaseAluOpcode::DivF:
            access.is_div = F(1);
            break;
    }
}
} // namespace recursion::alu_base
