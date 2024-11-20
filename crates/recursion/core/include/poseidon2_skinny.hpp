#pragma once

#include "prelude.hpp"

namespace sp1_recursion_core_sys::poseidon2_skinny {
template <class F>
__SP1_HOSTDEV__ void event_to_row(const Poseidon2Event<F>& event, size_t len,
                                  Poseidon2<F>* cols) {}

template <class F>
__SP1_HOSTDEV__ void instr_to_row(const Poseidon2Instr<F>& instr, size_t i,
                                  size_t len,
                                  Poseidon2PreprocessedColsSkinny<F>* cols) {}
}  // namespace sp1_recursion_core_sys::poseidon2_skinny
