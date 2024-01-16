use core::borrow::{Borrow, BorrowMut};
use std::mem::size_of;

use p3_field::PrimeField;
use std::vec::IntoIter;
use valida_derive::AlignedBorrow;

use crate::runtime::{Instruction, Opcode};

#[derive(AlignedBorrow, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct OpcodeSelectors<T> {
    // // Whether op_b is an immediate value.
    pub imm_b: T,
    // Whether op_c is an immediate value.
    pub imm_c: T,

    // Table selectors for opcodes.
    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
    pub is_div: T,
    pub is_shift: T,
    pub is_bitwise: T,
    pub is_lt: T,

    // Memory operation selectors.
    pub is_lb: T,
    pub is_lbu: T,
    pub is_lh: T,
    pub is_lhu: T,
    pub is_lw: T,
    pub is_sb: T,
    pub is_sh: T,
    pub is_sw: T,

    // Branch operation selectors.
    pub is_beq: T,
    pub is_bne: T,
    pub is_blt: T,
    pub is_bge: T,
    pub is_bltu: T,
    pub is_bgeu: T,

    // Jump instruction selectors.
    pub is_jalr: T,
    pub is_jal: T,

    pub is_auipc: T,

    // Whether this is a no-op.
    pub is_noop: T,
    pub reg_0_write: T,
}

impl<F: PrimeField> OpcodeSelectors<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        self.imm_b = F::from_bool(instruction.imm_b);
        self.imm_c = F::from_bool(instruction.imm_c);

        if instruction.is_alu_instruction() {
            match instruction.opcode {
                Opcode::ADD => {
                    self.is_add = F::one();
                }
                Opcode::SUB => {
                    self.is_sub = F::one();
                }
                Opcode::XOR | Opcode::OR | Opcode::AND => {
                    self.is_bitwise = F::one();
                }
                Opcode::SLL | Opcode::SRL | Opcode::SRA => {
                    self.is_shift = F::one();
                }
                Opcode::SLT | Opcode::SLTU => {
                    self.is_lt = F::one();
                }
                Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU => {
                    self.is_mul = F::one();
                }
                _ => {
                    panic!(
                        "unexpected opcode {} in register instruction table processing",
                        instruction.opcode
                    )
                }
            }
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

        if instruction.op_a == 0 {
            // If op_a is 0 and we're writing to the register, then we don't do a write.
            // We are always writing to the first register UNLESS it is a branch, is_store.
            if !(instruction.is_branch_instruction()
                || (self.is_sb + self.is_sh + self.is_sw) == F::one()
                || self.is_noop == F::one())
            {
                self.reg_0_write = F::one();
            }
        }
    }
}

impl<T> IntoIterator for OpcodeSelectors<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        vec![
            self.imm_b,
            self.imm_c,
            self.is_add,
            self.is_sub,
            self.is_mul,
            self.is_div,
            self.is_shift,
            self.is_bitwise,
            self.is_lt,
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
