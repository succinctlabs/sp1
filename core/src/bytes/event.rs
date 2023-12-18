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

    pub fn opcode(&self) -> ByteOpcode {
        self.opcode
    }

    pub fn and(&self, a: u8, b: u8) -> Self {
        Self::new(ByteOpcode::And, a, b, a & b)
    }

    pub fn or(&self, a: u8, b: u8) -> Self {
        Self::new(ByteOpcode::Or, a, b, a | b)
    }

    pub fn xor(&self, a: u8, b: u8) -> Self {
        Self::new(ByteOpcode::Xor, a, b, a ^ b)
    }

    pub fn sll(&self, a: u8, b: u8) -> Self {
        Self::new(ByteOpcode::SLL, a, b, a << b)
    }

    pub fn range(&self, a: u8, b: u8) -> Self {
        Self::new(ByteOpcode::Range, a, b, 0)
    }
}
