#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::batch_fri {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::BatchFRIEvent<F> &event, sp1_recursion_core_sys::BatchFRICols<F> &cols) {
    cols.acc = event.ext_single.acc;
    cols.alpha_pow = event.ext_vec.alpha_pow;
    cols.p_at_z = event.ext_vec.p_at_z;
    cols.p_at_x = event.base_vec.p_at_x;
}
} // namespace recursion::batch_fri
