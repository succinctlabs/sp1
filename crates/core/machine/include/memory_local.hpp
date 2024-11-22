#pragma once

#include "prelude.hpp"
#include "utils.hpp"
#include "bb31_septic_extension_t.hpp"

namespace sp1_core_machine_sys::memory_local {
    template<class F, class EF7> __SP1_HOSTDEV__ void populate_memory(GlobalInteractionOperation<F>* cols, const MemoryRecord* record, const uint32_t& addr, bool is_receive) {
        EF7 x_start;

        {
            x_start.value[0] = F::from_canonical_u32(record->shard + (1 << 24));
            x_start.value[1] = F::from_canonical_u32(record->timestamp);
            x_start.value[2] = F::from_canonical_u32(addr);
            x_start.value[3] = F::from_canonical_u32(record->value & 255);
            x_start.value[4] = F::from_canonical_u32((record->value >> 8) & 255);
            x_start.value[5] = F::from_canonical_u32((record->value >> 16) & 255);
            x_start.value[6] = F::from_canonical_u32((record->value >> 24) & 255);
        }

        /*EF7 y_start;

        {
            y_start.value[0] = F::from_canonical_u32(record->shard + (1 << 24));
            y_start.value[1] = F::from_canonical_u32(record->timestamp);
            y_start.value[2] = F::from_canonical_u32(addr);
            y_start.value[3] = F::from_canonical_u32(record->value & 255);
            y_start.value[4] = F::from_canonical_u32((record->value >> 8) & 255);
            y_start.value[5] = F::from_canonical_u32((record->value >> 16) & 255);
            y_start.value[6] = F::from_canonical_u32((record->value >> 24) & 255);
        }

        EF7 z_start;

        {
            z_start.value[0] = F::from_canonical_u32(record->shard + (1 << 24));
            z_start.value[1] = F::from_canonical_u32(record->timestamp);
            z_start.value[2] = F::from_canonical_u32(addr);
            z_start.value[3] = F::from_canonical_u32(record->value & 255);
            z_start.value[4] = F::from_canonical_u32((record->value >> 8) & 255);
            z_start.value[5] = F::from_canonical_u32((record->value >> 16) & 255);
            z_start.value[6] = F::from_canonical_u32((record->value >> 24) & 255);
        }

        EF7 w_start;

        {
            w_start.value[0] = F::from_canonical_u32(record->shard + (1 << 24));
            w_start.value[1] = F::from_canonical_u32(record->timestamp);
            w_start.value[2] = F::from_canonical_u32(addr);
            w_start.value[3] = F::from_canonical_u32(record->value & 255);
            w_start.value[4] = F::from_canonical_u32((record->value >> 8) & 255);
            w_start.value[5] = F::from_canonical_u32((record->value >> 16) & 255);
            w_start.value[6] = F::from_canonical_u32((record->value >> 24) & 255);
        }

        EF7 u_start;

        {
            u_start.value[0] = F::from_canonical_u32(record->shard + (1 << 24));
            u_start.value[1] = F::from_canonical_u32(record->timestamp);
            u_start.value[2] = F::from_canonical_u32(addr);
            u_start.value[3] = F::from_canonical_u32(record->value & 255);
            u_start.value[4] = F::from_canonical_u32((record->value >> 8) & 255);
            u_start.value[5] = F::from_canonical_u32((record->value >> 16) & 255);
            u_start.value[6] = F::from_canonical_u32((record->value >> 24) & 255);
        }

        EF7 v_start;

        {
            v_start.value[0] = F::from_canonical_u32(record->shard + (1 << 24));
            v_start.value[1] = F::from_canonical_u32(record->timestamp);
            v_start.value[2] = F::from_canonical_u32(addr);
            v_start.value[3] = F::from_canonical_u32(record->value & 255);
            v_start.value[4] = F::from_canonical_u32((record->value >> 8) & 255);
            v_start.value[5] = F::from_canonical_u32((record->value >> 16) & 255);
            v_start.value[6] = F::from_canonical_u32((record->value >> 24) & 255);
        }*/

        #pragma unroll(1)
        for(uint32_t offset = 0 ; offset < 256 ; offset++) {
            EF7 x_trial = x_start.universal_hash();
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
                cols->offset = F::from_canonical_u32(offset);
                for(uintptr_t i = 0 ; i < 7 ; i++) {
                    cols->x_coordinate._0[i] = x_trial.value[i];
                    cols->y_coordinate._0[i] = y.value[i];
                }
                uint32_t range_check_value;
                if (is_receive) {
                    range_check_value = y.value[6].as_canonical_u32() - 1;
                } else {
                    range_check_value = y.value[6].as_canonical_u32() - (F::MOD + 1) / 2;
                }
                write_word_from_u32_v2<F>(cols->y6_byte_decomp, range_check_value);
                return;
            }
            x_start += F::from_canonical_u32(1 << 16);
        }
        assert(false);
    }

    template<class F, class EF7>
    __SP1_HOSTDEV__ void event_to_row(const MemoryLocalEvent* event, SingleMemoryLocal<F>* cols) {
        populate_memory<F, EF7>(&cols->initial_global_interaction_cols, &event->initial_mem_access, event->addr, true);
        populate_memory<F, EF7>(&cols->final_global_interaction_cols, &event->final_mem_access, event->addr, false);
        cols->addr = F::from_canonical_u32(event->addr);
        
        cols->initial_shard = F::from_canonical_u32(event->initial_mem_access.shard);
        cols->initial_clk = F::from_canonical_u32(event->initial_mem_access.timestamp);
        write_word_from_u32_v2<F>(cols->initial_value, event->initial_mem_access.value);
        
        cols->final_shard = F::from_canonical_u32(event->final_mem_access.shard);
        cols->final_clk = F::from_canonical_u32(event->final_mem_access.timestamp);
        write_word_from_u32_v2<F>(cols->final_value, event->final_mem_access.value);

        cols->is_real = F::one();
    }
}  // namespace sp1::memory_local