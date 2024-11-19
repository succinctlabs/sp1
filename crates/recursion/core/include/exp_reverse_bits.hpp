#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::exp_reverse_bits {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::ExpReverseBitsEventC<F> &io, size_t i, sp1_recursion_core_sys::ExpReverseBitsLenCols<F> &cols) {
    cols.x = *io.base;
    cols.current_bit = io.exp_ptr[i];
    cols.multiplier = (io.exp_ptr[i] == F::one()) ? *io.base : F::one();
}
} // namespace recursion::exp_reverse_bits
