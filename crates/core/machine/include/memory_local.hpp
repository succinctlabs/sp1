#pragma once

#include "prelude.hpp"
#include "utils.hpp"

namespace sp1_core_machine_sys::memory_local {
    template<class F>
    __SP1_HOSTDEV__ void event_to_row(const MemoryLocalEvent& event, GlobalInteractionOperation<decltype(F::val)>& cols) {

    }
}  // namespace sp1::memory_local