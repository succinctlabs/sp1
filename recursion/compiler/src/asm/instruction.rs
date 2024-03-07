use crate::ir::F;
use core::fmt;

#[derive(Debug, Clone, Copy)]
pub enum Instruction {
    /// Load word
    LW(F, F),
    /// Store word
    SW(F, F),
    /// Add
    ADD(F, F, F),
    /// Add immediate
    ADDI(F, F, u32),
    /// Subtract
    SUB(F, F, F),
    /// Multiply
    MUL(F, F, F),
    /// Divide
    DIV(F, F, F),
    /// Jump
    JUMP(u32),
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Instruction::LW(dst, src) => write!(f, "lw ({})fp, ({})fp", dst, src),
            Instruction::SW(dst, src) => write!(f, "sw ({})fp, ({})fp", dst, src),
            Instruction::ADD(dst, lhs, rhs) => {
                write!(f, "add ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            Instruction::ADDI(dst, lhs, rhs) => write!(f, "addi ({})fp, ({})fp, {}", dst, lhs, rhs),
            Instruction::SUB(dst, lhs, rhs) => {
                write!(f, "sub ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            Instruction::MUL(dst, lhs, rhs) => {
                write!(f, "mul ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            Instruction::DIV(dst, lhs, rhs) => {
                write!(f, "div ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            Instruction::JUMP(label) => write!(f, "jump {}", label),
        }
    }
}
