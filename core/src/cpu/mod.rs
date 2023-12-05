pub mod air;
pub mod witness;

/// The `Word` type of our architecture.
pub struct Word(u32);
pub struct Pointer(u32);
pub struct Opcode(u8);

pub struct CPU {
    pub pc: Pointer,
    pub fp: Pointer,
    pub opcode: Opcode,
    pub operands: [Word; 3],
    pub immediate: Word,
}
