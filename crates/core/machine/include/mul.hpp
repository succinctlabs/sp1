#pragma once

#include "prelude.hpp"
#include "utils.hpp"

namespace sp1_core_machine_sys::mul {
template<class F>
__SP1_HOSTDEV__ void event_to_row(const AluEvent& event, MulCols<decltype(F::val)>& cols) {
    // // Ensure that the opcode is MUL, MULHU, MULH, or MULHSU.
    // assert!(
    //     event.opcode == Opcode::MUL
    //         || event.opcode == Opcode::MULHU
    //         || event.opcode == Opcode::MULH
    //         || event.opcode == Opcode::MULHSU
    // );

    const array_t<uint8_t, 4> a = u32_to_le_bytes(event.a);
    const array_t<uint8_t, 4> b = u32_to_le_bytes(event.b);
    const array_t<uint8_t, 4> c = u32_to_le_bytes(event.c);

    // Handle b and c's signs.
    {
        uint8_t b_msb = get_msb(b);
        cols.b_msb = F::from_canonical_u8(b_msb).val;
        uint8_t c_msb = get_msb(c);
        cols.c_msb = F::from_canonical_u8(c_msb).val;

        // If b is signed and it is negative, sign extend b.
        if ((event.opcode == Opcode::MULH || event.opcode == Opcode::MULHSU) && b_msb == 1) {
            cols.b_sign_extend = F::one().val;
        }

        // If c is signed and it is negative, sign extend c.
        if (event.opcode == Opcode::MULH && c_msb == 1) {
            cols.c_sign_extend = F::one().val;
        }

        //     // Insert the MSB lookup events.
        //     {
        //         let words = [b_word, c_word];
        //         let mut blu_events: Vec<ByteLookupEvent> = vec![];
        //         for word in words.iter() {
        //             let most_significant_byte = word[WORD_SIZE - 1];
        //             blu_events.push(ByteLookupEvent {
        //                 shard: event.shard,
        //                 opcode: ByteOpcode::MSB,
        //                 a1: get_msb(*word) as u16,
        //                 a2: 0,
        //                 b: most_significant_byte,
        //                 c: 0,
        //             });
        //         }
        //         record.add_byte_lookup_events(blu_events);
        //     }
    }

    // Required for the following logic to correctly multiply.
    static_assert(2 * WORD_SIZE == LONG_WORD_SIZE);

    array_t<uint32_t, LONG_WORD_SIZE> product {};
    for (uintptr_t i = 0; i < WORD_SIZE; ++i) {
        for (uintptr_t j = 0; j < WORD_SIZE; ++j) {
            product[i + j] += (uint32_t)b[i] * (uint32_t)c[j];
        }
        if (cols.c_sign_extend != F::zero().val) {
            for (uintptr_t j = WORD_SIZE; j < LONG_WORD_SIZE - i; ++j) {
                product[i + j] += (uint32_t)b[i] * (uint32_t)0xFF;
            }
        }
    }
    if (cols.b_sign_extend != F::zero().val) {
        for (uintptr_t i = WORD_SIZE; i < LONG_WORD_SIZE; ++i) {
            for (uintptr_t j = 0; j < LONG_WORD_SIZE - i; ++j) {
                product[i + j] += (uint32_t)0xFF * (uint32_t)c[j];
            }
        }
    }

    // Calculate the correct product using the `product` array. We store the
    // correct carry value for verification.
    const uint32_t base = 1 << BYTE_SIZE;
    array_t<uint32_t, LONG_WORD_SIZE> carry {};
    for (uintptr_t i = 0; i < LONG_WORD_SIZE; ++i) {
        carry[i] = product[i] / base;
        product[i] %= base;
        if (i + 1 < LONG_WORD_SIZE) {
            product[i + 1] += carry[i];
        }
        cols.carry[i] = F::from_canonical_u32(carry[i]).val;
    }

    for (uintptr_t i = 0; i < LONG_WORD_SIZE; ++i) {
        cols.product[i] = F::from_canonical_u32(product[i]).val;
    }
    word_from_le_bytes<F>(cols.a, a);
    word_from_le_bytes<F>(cols.b, b);
    word_from_le_bytes<F>(cols.c, c);
    cols.op_a_not_0 = F::from_bool(!event.op_a_0);
    cols.is_real = F::one().val;
    cols.is_mul = F::from_bool(event.opcode == Opcode::MUL).val;
    cols.is_mulh = F::from_bool(event.opcode == Opcode::MULH).val;
    cols.is_mulhu = F::from_bool(event.opcode == Opcode::MULHU).val;
    cols.is_mulhsu = F::from_bool(event.opcode == Opcode::MULHSU).val;
    cols.pc = F::from_canonical_u32(event.pc).val;

    // // Range check.
    // {
    //     record.add_u16_range_checks(event.shard, &carry.map(|x| x as u16));
    //     record.add_u8_range_checks(event.shard, &product.map(|x| x as u8));
    // }
}
}  // namespace sp1::mul
