#pragma once

#include "prelude.hpp"
#include "utils.hpp"
#include "bb31_septic_extension_t.hpp"
#include "memory_local.hpp"

namespace sp1_core_machine_sys::memory_global {
    template<class F, class EF7>
    __SP1_HOSTDEV__ void event_to_row(const MemoryInitializeFinalizeEvent* event, const bool is_receive, MemoryInitCols<F>* cols) {
        [[maybe_unused]]MemoryRecord record;
        if (is_receive) {
            record.shard = event->shard;
            record.timestamp = event->timestamp;
            record.value = event->value;
        } else {
            record.shard = 0;
            record.timestamp = 0;
            record.value = event->value;
        }
        cols->addr = F::from_canonical_u32(event->addr);
        for(uintptr_t i = 0 ; i < 32 ; i++) {
            cols->addr_bits.bits[i] = F::from_canonical_u32(((event->addr) >> i) & 1);
        }
        cols->addr_bits.and_most_sig_byte_decomp_3_to_5 = cols->addr_bits.bits[27] * cols->addr_bits.bits[28];
        cols->addr_bits.and_most_sig_byte_decomp_3_to_6 = cols->addr_bits.and_most_sig_byte_decomp_3_to_5 * cols->addr_bits.bits[29];
        cols->addr_bits.and_most_sig_byte_decomp_3_to_7 = cols->addr_bits.and_most_sig_byte_decomp_3_to_6 * cols->addr_bits.bits[30];
        cols->shard = F::from_canonical_u32(event->shard);
        cols->timestamp = F::from_canonical_u32(event->timestamp);
        for(uintptr_t i = 0 ; i < 32 ; i++) {
            cols->value[i] = F::from_canonical_u32(((event->value) >> i) & 1);
        }
        cols->is_real = F::from_canonical_u32(event->used);
    }
}  // namespace sp1::memory_local