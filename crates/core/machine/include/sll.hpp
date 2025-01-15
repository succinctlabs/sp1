#pragma once

#include <cstdlib>

#include "prelude.hpp"
#include "utils.hpp"

namespace sp1_core_machine_sys::sll {
template<class F>
__SP1_HOSTDEV__ void event_to_row(const AluEvent& event, ShiftLeftCols<decltype(F::val)>& cols) {
    array_t<uint8_t, 4> a = u32_to_le_bytes(event.a);
    array_t<uint8_t, 4> b = u32_to_le_bytes(event.b);
    array_t<uint8_t, 4> c = u32_to_le_bytes(event.c);
    cols.pc = F::from_canonical_u32(event.pc).val;
    word_from_le_bytes<F>(cols.a, a);
    word_from_le_bytes<F>(cols.b, b);
    word_from_le_bytes<F>(cols.c, c);
    cols.op_a_not_0 = F::from_bool(!event.op_a_0);
    cols.is_real = F::one().val;
    for (uintptr_t i = 0; i < BYTE_SIZE; ++i) {
        cols.c_least_sig_byte[i] = F::from_canonical_u32((event.c >> i) & 1).val;
    }

    // Variables for bit shifting.
    uintptr_t num_bits_to_shift = event.c % BYTE_SIZE;
    for (uintptr_t i = 0; i < BYTE_SIZE; ++i) {
        cols.shift_by_n_bits[i] = F::from_bool(num_bits_to_shift == i).val;
    }

    uint32_t bit_shift_multiplier = 1 << num_bits_to_shift;
    cols.bit_shift_multiplier = F::from_canonical_u32(bit_shift_multiplier).val;

    uint32_t carry = 0;
    uint32_t base = 1 << BYTE_SIZE;

    array_t<uint8_t, WORD_SIZE> bit_shift_result;
    array_t<uint8_t, WORD_SIZE> bit_shift_result_carry;
    for (uintptr_t i = 0; i < WORD_SIZE; ++i) {
        uint32_t v = b[i] * bit_shift_multiplier + carry;
        carry = v / base;
        bit_shift_result[i] = (uint8_t)(v % base);
        cols.bit_shift_result[i] = F::from_canonical_u8(bit_shift_result[i]).val;
        bit_shift_result_carry[i] = (uint8_t)carry;
        cols.bit_shift_result_carry[i] = F::from_canonical_u8(bit_shift_result_carry[i]).val;
    }

    // // Variables for byte shifting.
    uintptr_t num_bytes_to_shift = (uintptr_t)(event.c & 0b11111) / BYTE_SIZE;
    for (uintptr_t i = 0; i < WORD_SIZE; ++i) {
        cols.shift_by_n_bytes[i] = F::from_bool(num_bytes_to_shift == i).val;
    }

    // // Range checks.
    // {
    //     blu.add_u8_range_checks(event.shard, event.channel, &bit_shift_result);
    //     blu.add_u8_range_checks(event.shard, event.channel, &bit_shift_result_carry);
    // }

    // // Sanity check.
    // for i in num_bytes_to_shift..WORD_SIZE {
    //     debug_assert_eq!(
    //         cols.bit_shift_result[i - num_bytes_to_shift],
    //         F::from_canonical_u8(a[i])
    //     );
    // }
}
}  // namespace sp1::sll