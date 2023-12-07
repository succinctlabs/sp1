use super::ISA;

/// The base instruction set architecture.
#[derive(Clone, Debug, Copy)]
pub struct BaseISA;

#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub enum BaseInstruction {
    /// StoreWord(a, b).
    ///
    /// Loads the word at address fp+b into address fp+a.
    SW(u32, u32),
    /// ConstantWord(a, b).
    ///
    /// Stores the constant word into address fp+a.
    CW(u32, u32),
    /// Add(a, b, c)
    ///
    /// Adds the values at address fp+b and fp+c and stores the result in fp+a.
    ADD(u32, u32, u32),
    /// SUB(a, b, c)
    ///
    /// Subtracts the values at address fp+b and fp+c and stores the result in fp+a.
    SUB(u32, u32, u32),
    /// AND(a, b, c)
    ///
    /// Bitwise ANDs the values at address fp+b and fp+c and stores the result in fp+a.
    AND(u32, u32, u32),
    /// OR(a, b, c)
    ///
    /// Bitwise ORs the values at address fp+b and fp+c and stores the result in fp+a.
    OR(u32, u32, u32),
    /// XOR(a, b, c)
    ///
    /// Bitwise XORs the values at address fp+b and fp+c and stores the result in fp+a.
    XOR(u32, u32, u32),
    /// ADDI(a, b, d)
    ///
    /// Adds the value at address fp+b and the constant d and stores the result in fp+a.
    ADDI(u32, u32, u32),
    /// SUBI(a, b, d)
    ///
    /// Subtracts the value at address fp+b and the constant d and stores the result in fp+a.
    SUBI(u32, u32, u32),
    /// ANDI(a, b, d)
    ///
    /// Bitwise ANDs the value at address fp+b and the constant d and stores the result in fp+a.
    ANDI(u32, u32, u32),
    /// ORI(a, b, d)
    ///
    /// Bitwise ORs the value at address fp+b and the constant d and stores the result in fp+a.
    ORI(u32, u32, u32),
    /// XORI(a, b, d)
    ///
    /// Bitwise XORs the value at address fp+b and the constant d and stores the result in fp+a.
    XORI(u32, u32, u32),
    /// ECALL(a, b, c, d)
    ///
    /// Make an external call to the supporting execution environment.
    ECALL(u32, u32, u32, u32),
}

impl ISA for BaseISA {
    type Instruction = BaseInstruction;

    fn decode(instruction: &Self::Instruction) -> (u8, u32, u32, u32, u32) {
        match instruction {
            BaseInstruction::SW(a, b) => (0, *a, *b, 0, 0),
            BaseInstruction::CW(a, b) => (1, *a, *b, 0, 0),
            BaseInstruction::ADD(a, b, c) => (2, *a, *b, *c, 0),
            BaseInstruction::SUB(a, b, c) => (3, *a, *b, *c, 0),
            BaseInstruction::AND(a, b, c) => (4, *a, *b, *c, 0),
            BaseInstruction::OR(a, b, c) => (5, *a, *b, *c, 0),
            BaseInstruction::XOR(a, b, c) => (6, *a, *b, *c, 0),
            BaseInstruction::ADDI(a, b, d) => (7, *a, *b, 0, *d),
            BaseInstruction::SUBI(a, b, d) => (8, *a, *b, 0, *d),
            BaseInstruction::ANDI(a, b, d) => (9, *a, *b, 0, *d),
            BaseInstruction::ORI(a, b, d) => (10, *a, *b, 0, *d),
            BaseInstruction::XORI(a, b, d) => (11, *a, *b, 0, *d),
            BaseInstruction::ECALL(a, b, c, d) => (12, *a, *b, *c, *d),
        }
    }
}
