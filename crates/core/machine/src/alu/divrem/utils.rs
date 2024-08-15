use sp1_core_executor::Opcode;

/// Returns `true` if the given `opcode` is a signed operation.
pub fn is_signed_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIV || opcode == Opcode::REM
}

/// Calculate the correct `quotient` and `remainder` for the given `b` and `c` per RISC-V spec.
pub fn get_quotient_and_remainder(b: u32, c: u32, opcode: Opcode) -> (u32, u32) {
    if c == 0 {
        // When c is 0, the quotient is 2^32 - 1 and the remainder is b regardless of whether we
        // perform signed or unsigned division.
        (u32::MAX, b)
    } else if is_signed_operation(opcode) {
        ((b as i32).wrapping_div(c as i32) as u32, (b as i32).wrapping_rem(c as i32) as u32)
    } else {
        ((b as u32).wrapping_div(c as u32) as u32, (b as u32).wrapping_rem(c as u32) as u32)
    }
}

/// Calculate the most significant bit of the given 32-bit integer `a`, and returns it as a u8.
pub const fn get_msb(a: u32) -> u8 {
    ((a >> 31) & 1) as u8
}
