#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::batch_fri {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::BatchFRIEvent<F> &io, sp1_recursion_core_sys::ExtAluValueCols<F> &cols) {
  cols.vals = io;
}
} // namespace recursion::batch_fri
