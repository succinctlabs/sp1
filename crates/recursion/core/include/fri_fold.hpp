#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::fri_fold {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::FriFoldEvent<F> &event, sp1_recursion_core_sys::FriFoldCols<F> &cols) {
    cols.x = event.base_single.x;
    cols.z = event.ext_single.z;
    cols.alpha = event.ext_single.alpha;

    cols.p_at_z = event.ext_vec.ps_at_z;
    cols.p_at_x = event.ext_vec.mat_opening;
    cols.alpha_pow_input = event.ext_vec.alpha_pow_input;
    cols.ro_input = event.ext_vec.ro_input;

    cols.alpha_pow_output = event.ext_vec.alpha_pow_output;
    cols.ro_output = event.ext_vec.ro_output;
}
} // namespace recursion::fri_fold
