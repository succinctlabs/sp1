use core::fmt::Debug;

use super::Opcode;

/// An instruction specifies an operation to execute and the operands.
#[derive(Clone, Copy)]
pub struct Instruction {
    pub opcode: Opcode,
    pub op_a: u32,
    pub op_b: u32,
    pub op_c: u32,
    pub imm_b: bool,
    pub imm_c: bool,
}

impl Instruction {
    pub fn new(opcode: Opcode, op_a: u32, op_b: u32, op_c: u32, imm_b: bool, imm_c: bool) -> Self {
        Self {
            opcode,
            op_a,
            op_b,
            op_c,
            imm_b,
            imm_c,
        }
    }

    /// Returns if the instruction is an ALU instruction.
    pub fn is_alu_instruction(&self) -> bool {
        match self.opcode {
            Opcode::ADD
            | Opcode::SUB
            | Opcode::XOR
            | Opcode::OR
            | Opcode::AND
            | Opcode::SLL
            | Opcode::SRL
            | Opcode::SRA
            | Opcode::SLT
            | Opcode::SLTU
            | Opcode::MUL
            | Opcode::MULH
            | Opcode::MULHU
            | Opcode::MULHSU
            | Opcode::DIV
            | Opcode::DIVU
            | Opcode::REM
            | Opcode::REMU => true,
            _ => false,
        }
    }

    /// Returns if the instruction is a load instruction.
    pub fn is_load_instruction(&self) -> bool {
        match self.opcode {
            Opcode::LB | Opcode::LH | Opcode::LW | Opcode::LBU | Opcode::LHU => true,
            _ => false,
        }
    }

    /// Returns if the instruction is a store instruction.
    pub fn is_store_instruction(&self) -> bool {
        match self.opcode {
            Opcode::SB | Opcode::SH | Opcode::SW => true,
            _ => false,
        }
    }

    /// Returns if the instruction is a branch instruction.
    pub fn is_branch_instruction(&self) -> bool {
        match self.opcode {
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                true
            }
            _ => false,
        }
    }
}

impl Debug for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mnemonic = self.opcode.mnemonic();
        let op_a_formatted = format!("%x{}", self.op_a);
        let op_b_formatted = if self.imm_b || self.opcode == Opcode::AUIPC {
            format!("{}", self.op_b as i32)
        } else {
            format!("%x{}", self.op_b)
        };
        let op_c_formatted = if self.imm_c {
            format!("{}", self.op_c as i32)
        } else {
            format!("%x{}", self.op_c)
        };

        let width = 10;
        write!(
            f,
            "{:<width$} {:<width$} {:<width$} {:<width$}",
            mnemonic,
            op_a_formatted,
            op_b_formatted,
            op_c_formatted,
            width = width
        )
    }
}
