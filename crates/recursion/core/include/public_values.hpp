#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::public_values {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::CommitPublicValuesEvent<F> &event, size_t digest_idx, sp1_recursion_core_sys::PublicValuesCols<F> &cols) {
    cols.pv_element = event.public_values.digest[digest_idx];
}
} // namespace recursion::public_values
