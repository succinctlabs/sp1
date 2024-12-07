#pragma once

#include "prelude.hpp"
#include "utils.hpp"

namespace sp1_core_machine_sys::add_sub {
template<class F>
__SP1_HOSTDEV__ __SP1_INLINE__ uint32_t
populate(AddOperation<F>& op, const uint32_t a_u32, const uint32_t b_u32) {
    array_t<uint8_t, 4> a = u32_to_le_bytes(a_u32);
    array_t<uint8_t, 4> b = u32_to_le_bytes(b_u32);
    bool carry = a[0] + b[0] > 0xFF;
    op.carry[0] = F::from_bool(carry).val;
    carry = a[1] + b[1] + carry > 0xFF;
    op.carry[1] = F::from_bool(carry).val;
    carry = a[2] + b[2] + carry > 0xFF;
    op.carry[2] = F::from_bool(carry).val;

    uint32_t expected = a_u32 + b_u32;
    write_word_from_u32_v2<F>(op.value, expected);
    return expected;
}

template<class F>
__SP1_HOSTDEV__ void event_to_row(const AluEvent& event, AddSubCols<F>& cols) {
    cols.pc = F::from_canonical_u32(event.pc);

    bool is_add = event.opcode == Opcode::ADD;
    cols.is_add = F::from_bool(is_add);
    cols.is_sub = F::from_bool(!is_add);

    auto operand_1 = is_add ? event.b : event.a;
    auto operand_2 = event.c;

    populate<F>(cols.add_operation, operand_1, operand_2);
    write_word_from_u32_v2<F>(cols.operand_1, operand_1);
    write_word_from_u32_v2<F>(cols.operand_2, operand_2);
    cols.op_a_not_0 = F::from_bool(!event.op_a_0);
}
}  // namespace sp1::add_sub