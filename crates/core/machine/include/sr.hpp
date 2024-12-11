#pragma once

#include <cstdlib>

#include "prelude.hpp"
#include "utils.hpp"

namespace sp1_core_machine_sys::sr {
template<class F>
__SP1_HOSTDEV__ void event_to_row(const AluEvent& event, ShiftRightCols<decltype(F::val)>& cols) {
    // Initialize cols with basic operands and flags derived from the current event.
    {
        cols.pc = F::from_canonical_u32(event.pc).val;
        write_word_from_u32<F>(cols.a, event.a);
        write_word_from_u32<F>(cols.b, event.b);
        write_word_from_u32<F>(cols.c, event.c);
        cols.op_a_not_0 = F::from_bool(!event.op_a_0);
        cols.b_msb = F::from_canonical_u32((event.b >> 31) & 1).val;
        cols.is_srl = F::from_bool(event.opcode == Opcode::SRL).val;
        cols.is_sra = F::from_bool(event.opcode == Opcode::SRA).val;
        cols.is_real = F::one().val;

        for (uintptr_t i = 0; i < BYTE_SIZE; ++i) {
            cols.c_least_sig_byte[i] = F::from_canonical_u32((event.c >> i) & 1).val;
        }

        // // Insert the MSB lookup event.
        // let most_significant_byte = event.b.to_le_bytes()[WORD_SIZE - 1];
        // blu.add_byte_lookup_events(vec![ByteLookupEvent {
        //     shard: event.shard,
        //     opcode: ByteOpcode::MSB,
        //     a1: ((most_significant_byte >> 7) & 1) as u16,
        //     a2: 0,
        //     b: most_significant_byte,
        //     c: 0,
        // }]);
    }

    // Note that we take the least significant 5 bits per the RISC-V spec.
    const uintptr_t num_bytes_to_shift = (event.c % 32) / BYTE_SIZE;
    const uintptr_t num_bits_to_shift = (event.c % 32) % BYTE_SIZE;

    // Byte shifting.
    // Zero-initialize the array.
    array_t<uint8_t, LONG_WORD_SIZE> byte_shift_result {};
    {
        for (uintptr_t i = 0; i < WORD_SIZE; ++i) {
            cols.shift_by_n_bytes[i] = F::from_bool(num_bytes_to_shift == i).val;
        }
        // Sign extension is necessary only for arithmetic right shift.
        array_t<uint8_t, 8> sign_extended_b = event.opcode == Opcode::SRA
            ? u64_to_le_bytes((int64_t)(int32_t)event.b)
            : u64_to_le_bytes((uint64_t)event.b);

        for (uintptr_t i = 0; i < LONG_WORD_SIZE - num_bytes_to_shift; ++i) {
            byte_shift_result[i] = sign_extended_b[i + num_bytes_to_shift];
            cols.byte_shift_result[i] =
                F::from_canonical_u8(sign_extended_b[i + num_bytes_to_shift]).val;
        }
    }

    // Bit shifting.
    {
        for (uintptr_t i = 0; i < BYTE_SIZE; ++i) {
            cols.shift_by_n_bits[i] = F::from_bool(num_bits_to_shift == i).val;
        }
        const uint32_t carry_multiplier = 1 << (8 - num_bits_to_shift);
        uint32_t last_carry = 0;
        array_t<uint8_t, LONG_WORD_SIZE> bit_shift_result;
        array_t<uint8_t, LONG_WORD_SIZE> shr_carry_output_carry;
        array_t<uint8_t, LONG_WORD_SIZE> shr_carry_output_shifted_byte;
        for (intptr_t i = LONG_WORD_SIZE - 1; i >= 0; --i) {
            auto [shift, carry] = shr_carry(byte_shift_result[i], num_bits_to_shift);

            // let byte_event = ByteLookupEvent {
            //     shard: event.shard,
            //     opcode: ByteOpcode::ShrCarry,
            //     a1: shift as u16,
            //     a2: carry,
            //     b: byte_shift_result[i],
            //     c: num_bits_to_shift as u8,
            // };
            // blu.add_byte_lookup_event(byte_event);

            shr_carry_output_carry[i] = carry;
            cols.shr_carry_output_carry[i] = F::from_canonical_u8(carry).val;

            shr_carry_output_shifted_byte[i] = shift;
            cols.shr_carry_output_shifted_byte[i] = F::from_canonical_u8(shift).val;

            uint8_t res = (uint8_t)(((uint32_t)shift + last_carry * carry_multiplier) & 0xFF);
            bit_shift_result[i] = res;
            cols.bit_shift_result[i] = F::from_canonical_u8(res).val;
            last_carry = (uint32_t)carry;
        }
        // for (uintptr_t i = 0; i < WORD_SIZE; ++i)
        // {
        //     assert(cols.a[i] == cols.bit_shift_result[i]);
        // }
        // // Range checks.
        // blu.add_u8_range_checks(event.shard, &byte_shift_result);
        // blu.add_u8_range_checks(event.shard, &bit_shift_result);
        // blu.add_u8_range_checks(event.shard, &shr_carry_output_carry);
        // blu.add_u8_range_checks(event.shard, &shr_carry_output_shifted_byte);
    }
}
}  // namespace sp1::sr