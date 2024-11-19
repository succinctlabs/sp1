#pragma once

#include "prelude.hpp"
#include "utils.hpp"

namespace sp1::bitwise {
template<class F>
__SP1_HOSTDEV__ void event_to_row(const AluEvent& event, BitwiseCols<decltype(F::val)>& cols) {
    cols.shard = F::from_canonical_u32(event.shard).val;
    write_word_from_u32<F>(cols.a, event.a);
    write_word_from_u32<F>(cols.b, event.b);
    write_word_from_u32<F>(cols.c, event.c);
    cols.is_xor = F::from_bool(event.opcode == Opcode::XOR).val;
    cols.is_or = F::from_bool(event.opcode == Opcode::OR).val;
    cols.is_and = F::from_bool(event.opcode == Opcode::AND).val;

    // No byte lookup yet.
}
}  // namespace sp1::bitwise
