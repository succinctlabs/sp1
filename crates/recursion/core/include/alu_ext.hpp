#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::alu_ext {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::ExtAluIo<sp1_recursion_core_sys::Block<F>> &io, sp1_recursion_core_sys::ExtAluValueCols<F> &cols) {
  cols.vals.out = sp1_recursion_core_sys::Block<F>{io.out};
  cols.vals.in1 = sp1_recursion_core_sys::Block<F>{io.in1};
  cols.vals.in2 = sp1_recursion_core_sys::Block<F>{io.in2};
}
} // namespace recursion::alu_ext
