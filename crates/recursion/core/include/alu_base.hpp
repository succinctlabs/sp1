#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::alu_base {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::BaseAluIo<F> &io, sp1_recursion_core_sys::BaseAluValueCols<F> &cols) {
  cols.vals = io;
}
} // namespace recursion::alu_base
