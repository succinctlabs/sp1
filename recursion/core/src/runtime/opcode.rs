#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    // Arithmetic field instructions.
    ADD = 0,
    SUB = 1,
    MUL = 2,
    DIV = 3,

    // Arithmetic field extension operations.
    EAdd = 11,
    ESub = 12,
    EMul = 13,
    EDiv = 14,

    // Memory instructions.
    LW = 4,
    SW = 5,

    // Branch instructions.
    BEQ = 6,
    BNE = 7,

    // Jump instructions.
    JAL = 8,
    JALR = 9,

    // System instructions.
    TRAP = 10,
}
