use super::ISA;

pub struct Basic32;

pub enum BasicInstruction<W> {
    LW(W, W),
    SW(W, W),
    Const(W, W),
    Add(W, W, W),
}

impl ISA for Basic32 {
    type Opcode = u8;
    type Word = u32;
    type Instruction = BasicInstruction<u32>;
    type ImmValue = u32;
}
