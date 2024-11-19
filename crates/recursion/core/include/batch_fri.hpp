#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::batch_fri {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::BatchFRIEvent<F> &io, sp1_recursion_core_sys::BatchFRICols<F> &cols) {
    cols.acc = sp1_recursion_core_sys::Block<F>{io.base_vec.p_at_x};
    cols.alpha_pow = io.ext_vec.alpha_pow;
    cols.p_at_z = io.ext_vec.p_at_z;
    cols.p_at_x = io.ext_single.acc._0[0];
}
} // namespace recursion::batch_fri
