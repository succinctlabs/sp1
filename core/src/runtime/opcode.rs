use std::fmt::Display;

use p3_field::Field;
use serde::{Deserialize, Serialize};

/// An opcode specifies which operation to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[allow(non_camel_case_types)]
pub enum Opcode {
    // Arithmetic instructions.
    ADD = 0,
    SUB = 1,
    XOR = 2,
    OR = 3,
    AND = 4,
    SLL = 5,
    SRL = 6,
    SRA = 7,
    SLT = 8,
    SLTU = 9,

    // Load instructions.
    LB = 10,
    LH = 11,
    LW = 12,
    LBU = 13,
    LHU = 14,

    // Store instructions.
    SB = 15,
    SH = 16,
    SW = 17,

    // Branch instructions.
    BEQ = 18,
    BNE = 19,
    BLT = 20,
    BGE = 21,
    BLTU = 22,
    BGEU = 23,

    // Jump instructions.
    JAL = 24,
    JALR = 25,
    AUIPC = 27,

    // System instructions.
    ECALL = 28,
    EBREAK = 29,

    // Multiplication instructions.
    MUL = 30,
    MULH = 31,
    MULHU = 32,
    MULHSU = 33,
    DIV = 34,
    DIVU = 35,
    REM = 36,
    REMU = 37,

    // Miscellaneaous instructions.
    UNIMP = 39,
}

impl Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.mnemonic())
    }
}

impl Opcode {
    pub const fn mnemonic(&self) -> &str {
        match self {
            Opcode::ADD => "add",
            Opcode::SUB => "sub",
            Opcode::XOR => "xor",
            Opcode::OR => "or",
            Opcode::AND => "and",
            Opcode::SLL => "sll",
            Opcode::SRL => "srl",
            Opcode::SRA => "sra",
            Opcode::SLT => "slt",
            Opcode::SLTU => "sltu",
            Opcode::LB => "lb",
            Opcode::LH => "lh",
            Opcode::LW => "lw",
            Opcode::LBU => "lbu",
            Opcode::LHU => "lhu",
            Opcode::SB => "sb",
            Opcode::SH => "sh",
            Opcode::SW => "sw",
            Opcode::BEQ => "beq",
            Opcode::BNE => "bne",
            Opcode::BLT => "blt",
            Opcode::BGE => "bge",
            Opcode::BLTU => "bltu",
            Opcode::BGEU => "bgeu",
            Opcode::JAL => "jal",
            Opcode::JALR => "jalr",
            Opcode::AUIPC => "auipc",
            Opcode::ECALL => "ecall",
            Opcode::EBREAK => "ebreak",
            Opcode::MUL => "mul",
            Opcode::MULH => "mulh",
            Opcode::MULHU => "mulhu",
            Opcode::MULHSU => "mulhsu",
            Opcode::DIV => "div",
            Opcode::DIVU => "divu",
            Opcode::REM => "rem",
            Opcode::REMU => "remu",
            Opcode::UNIMP => "unimp",
        }
    }
}

impl Opcode {
    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u32(self as u32)
    }
}
