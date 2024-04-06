use p3_field::AbstractField;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    // Arithmetic field instructions.
    ADD = 0,
    SUB = 1,
    MUL = 2,
    DIV = 3,

    // Arithmetic field extension operations.
    EADD = 10,
    ESUB = 11,
    EMUL = 12,
    EDIV = 13,

    // Mixed arithmetic operations.
    EFADD = 20,
    EFSUB = 21,
    FESUB = 24,
    EFMUL = 22,
    EFDIV = 23,
    FEDIV = 25,

    // Memory instructions.
    LW = 4,
    SW = 5,
    LE = 14,
    SE = 15,

    // Branch instructions.
    BEQ = 6,
    BNE = 7,
    EBEQ = 16,
    EBNE = 17,

    // Jump instructions.
    JAL = 8,
    JALR = 9,

    // System instructions.
    TRAP = 30,

    // Hash instructions.
    Poseidon2Perm = 31,

    // Bit instructions.
    HintBits = 32,

    PrintF = 33,
    PrintE = 34,
    Ext2Felt = 35,

    FRIFold = 36,
}

impl Opcode {
    pub fn as_field<F: AbstractField>(&self) -> F {
        F::from_canonical_u32(*self as u32)
    }
}
