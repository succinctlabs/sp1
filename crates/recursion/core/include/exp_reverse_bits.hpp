#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::exp_reverse_bits {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::ExpReverseBitsEvent<F> &io, sp1_recursion_core_sys::ExpReverseBitsLenCols<F> &cols) {
    cols.x = io.base;
    cols.current_bit = io.exp[0];
    cols.multiplier = (io.exp[0] == F::one()) ? io.base : F::one();
}
} // namespace recursion::exp_reverse_bits
