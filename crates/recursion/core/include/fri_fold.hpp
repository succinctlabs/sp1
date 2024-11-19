#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::fri_fold {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::FriFoldEvent<F> &io, sp1_recursion_core_sys::FriFoldCols<F> &cols) {
    cols.x = io.base_single.x;
    cols.z = io.ext_single.z;
    cols.alpha = io.ext_single.alpha;

    cols.p_at_z = io.ext_vec.ps_at_z;
    cols.p_at_x = io.ext_vec.mat_opening;
    cols.alpha_pow_input = io.ext_vec.alpha_pow_input;
    cols.ro_input = io.ext_vec.ro_input;

    cols.alpha_pow_output = io.ext_vec.alpha_pow_output;
    cols.ro_output = io.ext_vec.ro_output;
}
} // namespace recursion::fri_fold
