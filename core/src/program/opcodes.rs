//! Succinct Base Integer Instructions

use std::{fmt::Display, fmt::Formatter};

pub const JAL: u32 = Opcode::JAL as u32;
pub const JALI: u32 = Opcode::JALI as u32;
pub const ADD: u32 = Opcode::ADD as u32;
pub const SUB: u32 = Opcode::SUB as u32;
pub const XOR: u32 = Opcode::XOR as u32;
pub const OR: u32 = Opcode::OR as u32;
pub const AND: u32 = Opcode::AND as u32;
pub const SLL: u32 = Opcode::SLL as u32;
pub const SRL: u32 = Opcode::SRL as u32;
pub const SRA: u32 = Opcode::SRA as u32;
pub const IMM: u32 = Opcode::IMM as u32;
pub const ADDI: u32 = Opcode::ADDI as u32;

// Let's turn these constants into an enum, so we can use them in a match statement. And when we
// do that, let's import all the comments we have in the constants above.

#[derive(Debug, Clone, Copy)]
pub enum Opcode {
    /// Jump and link. Set dest(fp) to `pc + 1`, then sets `pc` to `pc + offset`.
    JAL = 0x10,
    /// Indirect jump instruction. Sets dest(fp) to `pc + 1`, then sets `pc` to `a(fp) + offset`.
    JALI = 0x11,
    /// Set dest(fp) to a1(fp) + a2(d).
    ADD = 0x00,
    /// Set dest(fp) to a1(fp) + imm1.
    ADDI = 0x12,
    /// Set dest(fp) to a1(fp) - a2(fp).
    SUB = 0x01,
    /// Set dest(fp) to a1(fp) ^ a2(fp).
    XOR = 0x02,
    /// Set dest(fp) to a1(fp) | a2(fp).
    OR = 0x03,
    /// Set dest(fp) to a1(fp) & a2(fp).
    AND = 0x04,
    /// Set dest(fp) to a1(fp) << a2(fp).
    SLL = 0x05,
    /// Set dest(fp) to a1(fp) >> a2(fp).
    SRL = 0x06,
    /// Set dest(fp) to a1(fp) >>> a2(fp).
    SRA = 0x07,
    /// Set dest(fp) to imm.
    IMM = 0x09,
}

impl Opcode {
    pub fn from_u32(opcode: u32) -> Self {
        match opcode {
            JAL => Opcode::JAL,
            JALI => Opcode::JALI,
            ADD => Opcode::ADD,
            ADDI => Opcode::ADDI,
            SUB => Opcode::SUB,
            XOR => Opcode::XOR,
            OR => Opcode::OR,
            AND => Opcode::AND,
            SLL => Opcode::SLL,
            SRL => Opcode::SRL,
            SRA => Opcode::SRA,
            IMM => Opcode::IMM,
            _ => panic!("Invalid opcode"),
        }
    }
}

impl Display for Opcode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Opcode::JAL => write!(f, "JAL"),
            Opcode::JALI => write!(f, "JALI"),
            Opcode::ADD => write!(f, "ADD"),
            Opcode::ADDI => write!(f, "ADDI"),
            Opcode::SUB => write!(f, "SUB"),
            Opcode::XOR => write!(f, "XOR"),
            Opcode::OR => write!(f, "OR"),
            Opcode::AND => write!(f, "AND"),
            Opcode::SLL => write!(f, "SLL"),
            Opcode::SRL => write!(f, "SRL"),
            Opcode::SRA => write!(f, "SRA"),
            Opcode::IMM => write!(f, "IMM"),
        }
    }
}
