#pragma once

#include "prelude.hpp"
#include "utils.hpp"

namespace sp1_core_machine_sys::memory_local {
    template<class F, class EF7> __SP1_HOSTDEV__ __SP1_INLINE__ void populate_memory(GlobalInteractionOperation<F>& cols, const MemoryRecord& record, const uint32_t addr, bool is_receive) {
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
            F is_square = y_sq_pow_r ^ 1006632960;
            if(is_square == F::one()) {
                EF7 y = y_sq.sqrt(y_sq_pow_r);
                if (y.is_exception()) {
                    continue;
                }
                if (y.is_receive() != is_receive) {
                    y = EF7::zero() - y;
                }
                // x_trial, y
                cols.offset = F::from_canonical_u32(offset);
                for(uintptr_t i = 0 ; i < 7 ; i++) {
                    cols.x_coordinate._0[i] = x_trial.value[i];
                    cols.y_coordinate._0[i] = y.value[i];
                }
                uint32_t range_check_value;
                if (is_receive) {
                    range_check_value = y.value[6].as_canonical_u32() - 1;
                } else {
                    range_check_value = y.value[6].as_canonical_u32() - (F::MOD + 1) / 2;
                }
                write_word_from_u32_v2<F>(cols.y6_byte_decomp, range_check_value);
                return;
            }
        }
        assert(false);
    }

    template<class F, class EF7>
    __SP1_HOSTDEV__ void event_to_row(const MemoryLocalEvent& event, SingleMemoryLocal<F>& cols) {
        populate_memory<F, EF7>(cols.initial_global_interaction_cols, event.initial_mem_access, event.addr, true);
        populate_memory<F, EF7>(cols.final_global_interaction_cols, event.final_mem_access, event.addr, false);
        cols.addr = F::from_canonical_u32(event.addr).val;
        
        cols.initial_shard = F::from_canonical_u32(event.initial_mem_access.shard);
        cols.initial_clk = F::from_canonical_u32(event.initial_mem_access.timestamp);
        write_word_from_u32_v2<F>(cols.initial_value, event.initial_mem_access.value);
        
        cols.final_shard = F::from_canonical_u32(event.final_mem_access.shard);
        cols.final_clk = F::from_canonical_u32(event.final_mem_access.timestamp);
        write_word_from_u32_v2<F>(cols.final_value, event.final_mem_access.value);

        cols.is_real = F::one();
    }
}  // namespace sp1::memory_local