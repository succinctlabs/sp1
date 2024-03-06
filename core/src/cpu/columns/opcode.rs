use p3_field::PrimeField;
use sp1_derive::AlignedBorrow;
use std::mem::size_of;
use std::vec::IntoIter;

use crate::runtime::{Instruction, Opcode};

pub const NUM_OPCODE_SELECTOR_COLS: usize = size_of::<OpcodeSelectorCols<u8>>();

/// The column layout for opcode selectors.
#[derive(AlignedBorrow, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct OpcodeSelectorCols<T> {
    /// Whether op_b is an immediate value.
    pub imm_b: T,

    /// Whether op_c is an immediate value.
    pub imm_c: T,

    /// Table selectors for opcodes.
    pub is_alu: T,

    /// Memory Instructions.
    pub is_lb: T,
    pub is_lbu: T,
    pub is_lh: T,
    pub is_lhu: T,
    pub is_lw: T,
    pub is_sb: T,
    pub is_sh: T,
    pub is_sw: T,

    /// Branch Instructions.
    pub is_beq: T,
    pub is_bne: T,
    pub is_blt: T,
    pub is_bge: T,
    pub is_bltu: T,
    pub is_bgeu: T,

    /// Jump Instructions.
    pub is_jalr: T,
    pub is_jal: T,

    /// Miscellaneous.
    pub is_auipc: T,
    pub is_noop: T,
    pub reg_0_write: T,
}

impl<F: PrimeField> OpcodeSelectorCols<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        self.imm_b = F::from_bool(instruction.imm_b);
        self.imm_c = F::from_bool(instruction.imm_c);

        if instruction.is_alu_instruction() {
            self.is_alu = F::one();
        } else if instruction.is_memory_instruction() {
            match instruction.opcode {
                Opcode::LB => self.is_lb = F::one(),
                Opcode::LBU => self.is_lbu = F::one(),
                Opcode::LHU => self.is_lhu = F::one(),
                Opcode::LH => self.is_lh = F::one(),
                Opcode::LW => self.is_lw = F::one(),
                Opcode::SB => self.is_sb = F::one(),
                Opcode::SH => self.is_sh = F::one(),
                Opcode::SW => self.is_sw = F::one(),
                _ => unreachable!(),
            }
        } else if instruction.is_branch_instruction() {
            match instruction.opcode {
                Opcode::BEQ => self.is_beq = F::one(),
                Opcode::BNE => self.is_bne = F::one(),
                Opcode::BLT => self.is_blt = F::one(),
                Opcode::BGE => self.is_bge = F::one(),
                Opcode::BLTU => self.is_bltu = F::one(),
                Opcode::BGEU => self.is_bgeu = F::one(),
                _ => unreachable!(),
            }
        } else if instruction.opcode == Opcode::JAL {
            self.is_jal = F::one();
        } else if instruction.opcode == Opcode::JALR {
            self.is_jalr = F::one();
        } else if instruction.opcode == Opcode::AUIPC {
            self.is_auipc = F::one();
        } else if instruction.opcode == Opcode::UNIMP {
            self.is_noop = F::one();
        }

        // If op_a is 0 and we're writing to the register, then we don't do a write. We are always
        // writing to the first register UNLESS it is a branch, is_store.
        if instruction.op_a == 0
            && !(instruction.is_branch_instruction()
                || (self.is_sb + self.is_sh + self.is_sw) == F::one()
                || self.is_noop == F::one())
        {
            self.reg_0_write = F::one();
        }
    }
}

impl<T> IntoIterator for OpcodeSelectorCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        vec![
            self.imm_b,
            self.imm_c,
            self.is_alu,
            self.is_lb,
            self.is_lbu,
            self.is_lh,
            self.is_lhu,
            self.is_lw,
            self.is_sb,
            self.is_sh,
            self.is_sw,
            self.is_beq,
            self.is_bne,
            self.is_blt,
            self.is_bge,
            self.is_bltu,
            self.is_bgeu,
            self.is_jalr,
            self.is_jal,
            self.is_auipc,
            self.is_noop,
            self.reg_0_write,
        ]
        .into_iter()
    }
}
