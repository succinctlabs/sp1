use super::ByteOpcode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteLookupEvent {
    pub opcode: ByteOpcode,
    pub a: u8,
    pub b: u8,
    pub c: u8,
}

impl ByteLookupEvent {
    pub fn new(opcode: ByteOpcode, a: u8, b: u8, c: u8) -> Self {
        Self { opcode, a, b, c }
    }
}
