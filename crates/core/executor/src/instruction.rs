//! Instructions for the SP1 zkVM.

use core::fmt::Debug;
use serde::{Deserialize, Serialize};

use crate::opcode::Opcode;

/// RISC-V 32IM Instruction.
///
/// The structure of the instruction differs from the RISC-V ISA. We do not encode the instructions
/// as 32-bit words, but instead use a custom encoding that is more friendly to decode in the
/// SP1 zkVM.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Instruction {
    /// The operation to execute.
    pub opcode: Opcode,
    /// The first operand.
    pub op_a: u32,
    /// The second operand.
    pub op_b: u32,
    /// The third operand.
    pub op_c: u32,
    /// Whether the second operand is an immediate value.
    pub imm_b: bool,
    /// Whether the third operand is an immediate value.
    pub imm_c: bool,
}

impl Instruction {
    /// Create a new [`RiscvInstruction`].
    #[must_use]
    pub const fn new(
        opcode: Opcode,
        op_a: u32,
        op_b: u32,
        op_c: u32,
        imm_b: bool,
        imm_c: bool,
    ) -> Self {
        Self { opcode, op_a, op_b, op_c, imm_b, imm_c }
    }

    /// Returns if the instruction is an ALU instruction.
    #[must_use]
    pub const fn is_alu_instruction(&self) -> bool {
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

    /// Returns if the instruction is a ecall instruction.
    #[must_use]
    pub fn is_ecall_instruction(&self) -> bool {
        self.opcode == Opcode::ECALL
    }

    /// Returns if the instruction is a memory instruction.
    #[must_use]
    pub const fn is_memory_instruction(&self) -> bool {
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
    #[must_use]
    pub const fn is_branch_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU
        )
    }

    /// Returns if the instruction is a jump instruction.
    #[must_use]
    pub const fn is_jump_instruction(&self) -> bool {
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
        let op_c_formatted =
            if self.imm_c { format!("{}", self.op_c as i32) } else { format!("%x{}", self.op_c) };

        let width = 10;
        write!(
            f,
            "{mnemonic:<width$} {op_a_formatted:<width$} {op_b_formatted:<width$} {op_c_formatted:<width$}"
        )
    }
}
