#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::alu_ext {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::ExtAluIo<sp1_recursion_core_sys::Block<F>> &io, sp1_recursion_core_sys::ExtAluValueCols<F> &cols) {
  cols.vals = io;
}
} // namespace recursion::alu_ext
