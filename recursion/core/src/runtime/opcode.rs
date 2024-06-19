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
    LOAD = 4,
    STORE = 5,

    // Branch instructions.
    BEQ = 6,
    BNE = 7,

    // Jump instructions.
    JAL = 8,
    JALR = 9,

    // System instructions.
    TRAP = 30,
    HALT = 31,

    // Poseidon2 compress.
    Poseidon2Compress = 39,

    // Poseidon2 hash.
    Poseidon2Absorb = 46,
    Poseidon2Finalize = 47,

    // Bit instructions.
    HintBits = 32,

    PrintF = 33,
    PrintE = 34,
    HintExt2Felt = 35,

    FRIFold = 36,
    HintLen = 37,
    Hint = 38,
    BNEINC = 40,
    Commit = 41,
    RegisterPublicValue = 42,
    LessThanF = 43,
    CycleTracker = 44,
    ExpReverseBitsLen = 45,
}

impl Opcode {
    pub fn as_field<F: AbstractField>(&self) -> F {
        F::from_canonical_u32(*self as u32)
    }
}
