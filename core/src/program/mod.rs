pub mod basic;

/// An instruction set architecture.
///
/// This trait defines the basic types needed to encode an instruction.
pub trait ISA {
    /// The opcode type of our architecture.
    ///
    /// Opcodes are used to encode instructions.
    type Opcode;

    /// The word type of our architecture.
    ///
    /// Words are used to encode addresses and data in memory.
    type Word: Copy + Default;

    type Instruction;
    /// The immediate value type of our architecture.
    ///
    /// Immediate values are used to encode constants in instructions.
    type ImmValue;
}
