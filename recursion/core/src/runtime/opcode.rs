use p3_field::AbstractField;
use serde::{Deserialize, Serialize};

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    HintLen = 37,
    Hint = 38,
    Poseidon2Compress = 39,
    BNEINC = 40,
    Commit = 41,
    LessThanF = 42,
    CycleTracker = 43,
}

impl Opcode {
    pub fn as_field<F: AbstractField>(&self) -> F {
        F::from_canonical_u32(*self as u32)
    }
}
