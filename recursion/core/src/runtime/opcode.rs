#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    // Arithmetic field instructions.
    ADD = 0,
    SUB = 1,
    MUL = 2,
    DIV = 3,

    // Arithmetic field extension operations.
    EADD = 11,
    ESUB = 12,
    EMUL = 13,
    EDIV = 14,

    // Memory instructions.
    LW = 4,
    SW = 5,

    // Branch instructions.
    BEQ = 6,
    BNE = 7,
    EBEQ = 15,
    EBNE = 16,

    // Jump instructions.
    JAL = 8,
    JALR = 9,

    // System instructions.
    TRAP = 10,
}
