pub mod air;
pub mod trace;

#[derive(Debug, Clone, Copy)]
pub struct ByteChip;

pub const NUM_BYTE_OPS: usize = core::mem::variant_count::<ByteOpcode>();

#[derive(Debug, Clone, Copy)]
pub enum ByteOpcode {
    /// Bitwise AND.
    And = 0,
    /// Bitwise OR.
    Or = 1,
    /// Bitwise XOR.
    Xor = 2,
    /// Bit-shift Left.
    SLL = 3,
    /// Bit-shift Right.
    SRL = 4,
    /// Range check.
    Range = 5,
}
