pub mod base;

/// An instruction set architecture with 32-bit addresses.
///
/// This trait defines the basic types needed to encode an instruction.
pub trait ISA {
    /// The instruction type of our architecture.
    type Instruction;

    /// Decode an instruction to its opcode and arguments.
    ///
    /// The instruction is deconded as `(opcode, op_a, op_b, op_c, imm)`. This enforces a standard
    /// format for instructions that can be used by the runtime.
    fn decode(instruction: &Self::Instruction) -> (u8, u32, u32, u32, u32);
}
