use std::{array, fmt::Display};

use itertools::Itertools;
use p3_field::{AbstractField, Field};
use serde::{Deserialize, Serialize};
use strum::VariantArray;

/// An opcode specifies which operation to execute.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, VariantArray,
)]
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

    pub const fn max_opcode_value() -> usize {
        let variants = Self::VARIANTS;
        let mut max_num = variants[0] as usize;
        let mut i = 1;

        while i < variants.len() {
            let num = variants[i] as usize;
            if num > max_num {
                max_num = num;
            }

            i += 1;
        }

        max_num
    }

    pub const fn num_bits_for_opcode() -> usize {
        Self::max_opcode_value()
            .next_power_of_two()
            .trailing_zeros() as usize
    }

    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u32(self as u32)
    }

    pub fn as_le_bits<F: AbstractField>(self) -> [F; Self::num_bits_for_opcode()] {
        let bits: [F; Self::num_bits_for_opcode()] =
            array::from_fn(|i| F::from_bool((self as usize) & (1 << i) != 0));

        bits
    }

    pub fn is_eq_from_bits<F: AbstractField>(self, rhs: [F; Self::num_bits_for_opcode()]) -> F {
        let lhs = self.as_le_bits::<F>();
        let bitwse_xor: [F; Self::num_bits_for_opcode()] = array::from_fn(|i| {
            let xor = lhs[i] + rhs[i] - F::from_canonical_usize(2) * lhs[i] * rhs[i];
            F::one() - xor
        });

        bit_eq.eq
    }
}
