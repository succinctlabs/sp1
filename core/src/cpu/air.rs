use crate::Word;

pub struct CPUTable<F> {
    pub pc: F,
    pub fp: F,
    pub opcode: F,
    pub operands: [Word<F>; 3],
}
