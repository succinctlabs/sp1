use super::ByteOpcode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteLookupEvent {
    pub opcode: ByteOpcode,
    pub a1: u8,
    pub a2: u8,
    pub b: u8,
    pub c: u8,
}

impl ByteLookupEvent {
    pub const fn new(opcode: ByteOpcode, a1: u8, a2: u8, b: u8, c: u8) -> Self {
        Self {
            opcode,
            a1,
            a2,
            b,
            c,
        }
    }
}
