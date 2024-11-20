#pragma once

#include "prelude.hpp"

namespace sp1_recursion_core_sys::poseidon2_skinny
{
    template <class F>
    __SP1_HOSTDEV__ void event_to_row(const Poseidon2Event<F> &event, Poseidon2FFI<F> &cols[NUM_EXTERNAL_ROUNDS + 3])
    {
        cols.vals = event;
    }
}
