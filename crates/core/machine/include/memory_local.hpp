#pragma once

#include "prelude.hpp"
#include "utils.hpp"

namespace sp1_core_machine_sys::memory_local {
    template<class F, class EF7> __SP1_HOSTDEV__ __SP1_INLINE__ void populate_memory(GlobalInteractionOperation<decltype(F::val)>& cols, const MemoryRecord& record, const uint32_t addr, bool is_receive) {
        F value[7];
        value[0] = F::from_canonical_u32(record.shard + (1 << 24));
        value[1] = F::from_canonical_u32(record.timestamp);
        value[2] = F::from_canonical_u32(addr);
        value[3] = F::from_canonical_u32(record.value & 255);
        value[4] = F::from_canonical_u32((record.value >> 8) & 255);
        value[5] = F::from_canonical_u32((record.value >> 16) & 255);
        value[6] = F::from_canonical_u32((record.value >> 24) & 255);

        EF7 x_start = EF7(value);
        for(uint32_t offset = 0 ; offset < 256 ; offset++) {
            EF7 m_trial = x_start + F::from_canonical_u32(offset << 16);
            EF7 x_trial = m_trial.universal_hash();
            EF7 y_sq = x_trial.curve_formula();
            F y_sq_pow_r = y_sq.pow_r();
            if(y_sq_pow_r.is_square()) {
                break;
            }
            
        }


    }

    template<class F, class EF7>
    __SP1_HOSTDEV__ void event_to_row(const MemoryLocalEvent& event, GlobalInteractionOperation<decltype(F::val)>& cols_init, GlobalInteractionOperation<decltype(F::val)>& cols_final) {
        populate_memory<F, EF7>(cols_init, event.initial_mem_access, event.addr, true);
        populate_memory<F, EF7>(cols_final, event.final_mem_access, event.addr, false);
    }
}  // namespace sp1::memory_local