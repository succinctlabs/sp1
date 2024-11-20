#pragma once

#include "sp1_recursion_core_sys-cbindgen.hpp"

namespace recursion::public_values {
template <class F> __SP1_HOSTDEV__ void event_to_row(const sp1_recursion_core_sys::CommitPublicValuesEvent<F> &event, size_t digest_idx, sp1_recursion_core_sys::PublicValuesCols<F> &cols) {
    cols.pv_element = event.public_values.digest[digest_idx];
}

template <class F> __SP1_HOSTDEV__ void instr_to_row(const sp1_recursion_core_sys::CommitPublicValuesInstr<F> &instr, size_t digest_idx, sp1_recursion_core_sys::PublicValuesPreprocessedCols<F> &cols) {
    cols.pv_idx[digest_idx] = F::one();
    cols.pv_mem.addr = instr.pv_addrs.digest[digest_idx];
    cols.pv_mem.mult = F::zero() - F::one();
}
} // namespace recursion::public_values
