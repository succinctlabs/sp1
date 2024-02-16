use core::fmt::Debug;

use super::{Opcode, SyscallCode};

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
        matches!(
            self.opcode,
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
                | Opcode::REMU
        )
    }

    /// Returns if the instruction is a precompile instruction.
    pub fn is_precompile_instruction(&self) -> bool {
        if self.opcode == Opcode::ECALL {
            println!("Found an ECALL instruction: {:#?}", self);
            println!("opcode: {}", self.opcode);
            println!("op_a: {}", self.op_a);
            println!("op_b: {}", self.op_b);
            println!("op_c: {}", self.op_c);
            println!("imm_b: {}", self.imm_b);
            println!("imm_c: {}", self.imm_c);
            if (self.opcode == Opcode::ECALL)
                && (self.op_a == SyscallCode::BLAKE3_COMPRESS_INNER as u32)
            {
                println!("It's Blake3!");
            } else {
                println!("It's not Blake3!");
            }
        }
        // TODO: Obviously, I have to add other precompiles here. But for now, I'll use Blake3 as an
        // example.
        (self.opcode == Opcode::ECALL) && (self.op_a == SyscallCode::BLAKE3_COMPRESS_INNER as u32)
    }

    /// Returns if the instruction is a memory instruction.
    pub fn is_memory_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::LB
                | Opcode::LH
                | Opcode::LW
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::SB
                | Opcode::SH
                | Opcode::SW
        )
    }

    /// Returns if the instruction is a branch instruction.
    pub fn is_branch_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU
        )
    }

    pub fn is_jump_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::JAL | Opcode::JALR)
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
