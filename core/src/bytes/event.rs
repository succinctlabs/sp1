use super::ByteOpcode;

/// A byte lookup event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteLookupEvent {
    /// The opcode of the operation.
    pub opcode: ByteOpcode,

    /// The first output operand.
    pub a1: u8,

    /// The second output operand.
    pub a2: u8,

    /// The first input operand.
    pub b: u8,

    /// The second input operand.
    pub c: u8,
}

impl ByteLookupEvent {
    /// Creates a new `ByteLookupEvent`.
    pub fn new(opcode: ByteOpcode, a1: u8, a2: u8, b: u8, c: u8) -> Self {
        Self {
            opcode,
            a1,
            a2,
            b,
            c,
        }
    }
}
