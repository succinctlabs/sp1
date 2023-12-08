pub struct ValidaISA;

pub enum Instruction {
    Add(u32, u32, u32),
    Addi(u32, u32, u32),
    Const(u32, u32),
    LW(u32, u32),
    SW(u32, u32),
}
