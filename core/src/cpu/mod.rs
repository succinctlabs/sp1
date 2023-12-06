use crate::program::ISA;

pub mod air;
pub mod witness;

/// The `Opcode` type of our architecture.

pub struct Cpu<IS: ISA> {
    pub pc: IS::Word,
    pub fp: IS::Word,
    pub opcode: IS::Opcode,
    pub operands: [IS::Word; 3],
    pub immediate: IS::ImmValue,
}
