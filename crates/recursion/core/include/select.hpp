#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::select {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::SelectEvent<F> &io, sp1_recursion_core_sys::SelectCols<F> &cols) {
    cols.vals = io;
}
} // namespace recursion::select
