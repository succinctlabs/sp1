#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone)]
pub enum Opcode {
    // Arithmetic instructions.
    ADD = 0,
    SUB = 1,
    MUL = 2,
    DIV = 3,

    // Memory instructions.
    LW = 4,
    SW = 5,

    // Branch instructions.
    BEQ = 6,
    BNE = 7,

    // Jump instructions.
    JAL = 8,
    JALR = 9,
}
