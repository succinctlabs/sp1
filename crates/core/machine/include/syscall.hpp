#pragma once

#include "prelude.hpp"
#include "utils.hpp"
#include "bb31_septic_extension_t.hpp"

namespace sp1_core_machine_sys::syscall {
    template<class F, class EF7>
    __SP1_HOSTDEV__ void event_to_row(const SyscallEvent* event, const bool is_receive, SyscallCols<F>* cols) {
        cols->shard = F::from_canonical_u32(event->shard);
        cols->clk = F::from_canonical_u32(event->clk);
        cols->syscall_id = F::from_canonical_u32(event->syscall_id);
        cols->arg1 = F::from_canonical_u32(event->arg1);
        cols->arg2 = F::from_canonical_u32(event->arg2);
        cols->is_real = F::one();
    }
}  // namespace sp1::memory_local
