#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::alu_ext {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::ExtAluEvent<F> &event, sp1_recursion_core_sys::ExtAluValueCols<F> &cols) {
  cols.vals = event;
}
} // namespace recursion::alu_ext
