#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::select {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::SelectEvent<F> &event, sp1_recursion_core_sys::SelectCols<F> &cols) {
    cols.vals = event;
}

template <class F> __SP1_HOSTDEV__ void instr_to_row(const sp1_recursion_core_sys::SelectInstr<F> &instr, sp1_recursion_core_sys::SelectPreprocessedCols<F> &cols) {
    cols.is_real = F::one();
    cols.addrs = instr.addrs;
    cols.mult1 = instr.mult1;
    cols.mult2 = instr.mult2;
}
} // namespace recursion::select
