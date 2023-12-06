use curta_core::program::ISA;

pub struct ValidaISA;

impl ISA for ValidaISA {
    type Opcode = u8;
    type Word = u32;
    type Instruction = Instruction;
    type ImmValue = u32;
}

pub enum Instruction {
    Add(u32, u32, u32),
    Addi(u32, u32, u32),
    Const(u32, u32),
    LW(u32, u32),
    SW(u32, u32),
}
