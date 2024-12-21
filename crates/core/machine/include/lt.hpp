#pragma once

#include <cstdlib>

#include "prelude.hpp"
#include "utils.hpp"

namespace sp1_core_machine_sys::lt {
template<class F>
__SP1_HOSTDEV__ void event_to_row(const AluEvent& event, LtCols<F>& cols) {
    array_t<uint8_t, 4> a = u32_to_le_bytes(event.a);
    array_t<uint8_t, 4> b = u32_to_le_bytes(event.b);
    array_t<uint8_t, 4> c = u32_to_le_bytes(event.c);

    cols.pc = F::from_canonical_u32(event.pc).val;
    word_from_le_bytes<F>(cols.a, a);
    word_from_le_bytes<F>(cols.b, b);
    word_from_le_bytes<F>(cols.c, c);
    cols.op_a_not_0 = F::from_bool(!event.op_a_0);

    // If this is SLT, mask the MSB of b & c before computing cols.bits.
    uint8_t masked_b = b[3] & 0x7f;
    uint8_t masked_c = c[3] & 0x7f;
    cols.b_masked = F::from_canonical_u8(masked_b);
    cols.c_masked = F::from_canonical_u8(masked_c);

    // // Send the masked interaction.
    // blu.add_byte_lookup_event(ByteLookupEvent {
    //     shard: event.shard,
    //     channel: event.channel,
    //     opcode: ByteOpcode::AND,
    //     a1: masked_b as u16,
    //     a2: 0,
    //     b: b[3],
    //     c: 0x7f,
    // });
    // blu.add_byte_lookup_event(ByteLookupEvent {
    //     shard: event.shard,
    //     channel: event.channel,
    //     opcode: ByteOpcode::AND,
    //     a1: masked_c as u16,
    //     a2: 0,
    //     b: c[3],
    //     c: 0x7f,
    // });

    array_t<uint8_t, 4> b_comp = b;
    array_t<uint8_t, 4> c_comp = c;
    if (event.opcode == Opcode::SLT) {
        b_comp[3] = masked_b;
        c_comp[3] = masked_c;
    }

    // Set the byte equality flags.
    intptr_t i = 3;
    while (true) {
        uint8_t b_byte = b_comp[i];
        uint8_t c_byte = c_comp[i];
        if (b_byte != c_byte) {
            cols.byte_flags[i] = F::one();
            cols.sltu = F::from_bool(b_byte < c_byte);
            F b_byte_f = F::from_canonical_u8(b_byte);
            F c_byte_f = F::from_canonical_u8(c_byte);
            cols.not_eq_inv = (b_byte_f - c_byte_f).reciprocal();
            cols.comparison_bytes[0] = b_byte_f;
            cols.comparison_bytes[1] = c_byte_f;
            break;
        }
        if (i == 0) {
            // The equality `b_comp == c_comp` holds.
            cols.is_comp_eq = F::one();
            break;
        }
        --i;
    }

    cols.msb_b = F::from_bool((b[3] >> 7) & 1);
    cols.msb_c = F::from_bool((c[3] >> 7) & 1);
    cols.is_sign_eq = F::from_bool(event.opcode != Opcode::SLT || cols.msb_b == cols.msb_c);

    cols.is_slt = F::from_bool(event.opcode == Opcode::SLT);
    cols.is_sltu = F::from_bool(event.opcode == Opcode::SLTU);

    cols.bit_b = (F(cols.msb_b) * F(cols.is_slt));
    cols.bit_c = (F(cols.msb_c) * F(cols.is_slt));

    // if (F(cols.a._0[0]) != F(cols.bit_b) * (F::one() - F(cols.bit_c)) + F(cols.is_sign_eq) * F(cols.sltu))
    // {
    //     std::exit(1);
    // }

    // blu.add_byte_lookup_event(ByteLookupEvent {
    //     shard: event.shard,
    //     channel: event.channel,
    //     opcode: ByteOpcode::LTU,
    //     a1: cols.sltu.as_canonical_u32() as u16,
    //     a2: 0,
    //     b: cols.comparison_bytes[0].as_canonical_u32() as u8,
    //     c: cols.comparison_bytes[1].as_canonical_u32() as u8,
    // });
}
}  // namespace sp1::lt