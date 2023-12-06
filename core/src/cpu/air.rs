use crate::Word;

/// The AIR table for the CPU.
pub struct CPUTable<F> {
    pub pc: F,
    pub fp: F,
    pub opcode: F,
    pub op_a: Word<F>,
    pub op_b: Word<F>,
    pub op_c: Word<F>,
    pub imm: Word<F>,
}
