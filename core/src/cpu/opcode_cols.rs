use core::borrow::{Borrow, BorrowMut};
use p3_air::AirBuilder;
use p3_field::PrimeField;
use valida_derive::AlignedBorrow;

use crate::runtime::{Instruction, Opcode};

#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
pub struct OpcodeSelectors<T> {
    // // Whether op_b is an immediate value.
    pub imm_b: T,
    // Whether op_c is an immediate value.
    pub imm_c: T,

    // ALU ops
    pub add_op: T,
    pub sub_op: T,
    pub mul_op: T,
    pub div_op: T,
    pub shift_op: T,
    pub bitwise_op: T,
    pub lt_op: T,

    // Memory ops
    pub is_load: T,
    pub is_store: T,
    pub is_word: T,
    pub is_half: T,
    pub is_byte: T,
    pub is_signed: T,

    // Branch ops
    pub is_beq: T,
    pub is_bne: T,
    pub is_blt: T,
    pub is_bge: T,
    pub is_bltu: T,
    pub is_bgeu: T,

    // Whether this is a no-op.
    pub noop: T,

    // Specific instruction selectors.
    pub jalr: T,
    pub jal: T,
    pub auipc: T,

    pub reg_0_write: T,
}

impl<F: PrimeField> OpcodeSelectors<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        self.imm_b = F::from_bool(instruction.imm_b);
        self.imm_c = F::from_bool(instruction.imm_c);

        let mut is_store = false;
        if instruction.is_alu_instruction() {
            match instruction.opcode {
                Opcode::ADD => {
                    self.add_op = F::one();
                }
                Opcode::SUB => {
                    self.sub_op = F::one();
                }
                Opcode::XOR | Opcode::OR | Opcode::AND => {
                    self.bitwise_op = F::one();
                }
                Opcode::SLL | Opcode::SRL | Opcode::SRA => {
                    self.shift_op = F::one();
                }
                Opcode::SLT | Opcode::SLTU => {
                    self.lt_op = F::one();
                }
                Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU => {}
                _ => {
                    panic!(
                        "unexpected opcode {} in register instruction table processing",
                        instruction.opcode
                    )
                }
            }
        } else if instruction.is_load_instruction() {
            self.is_load = F::one();

            match instruction.opcode {
                Opcode::LB => {
                    self.is_byte = F::one();
                    self.is_signed = F::one();
                }
                Opcode::LBU => {
                    self.is_byte = F::one();
                }
                Opcode::LHU => {
                    self.is_half = F::one();
                }
                Opcode::LH => {
                    self.is_half = F::one();
                    self.is_signed = F::one();
                }
                Opcode::LW => {
                    self.is_word = F::one();
                }
                _ => unreachable!(),
            }
        } else if instruction.is_store_instruction() {
            self.is_store = F::one();

            match instruction.opcode {
                Opcode::SB => {
                    self.is_byte = F::one();
                }
                Opcode::SH => {
                    self.is_half = F::one();
                }
                Opcode::SW => {
                    self.is_word = F::one();
                }
                _ => unreachable!(),
            }
        } else if instruction.is_branch_instruction() {
            match instruction.opcode {
                Opcode::BEQ => {
                    self.is_beq = F::one();
                }
                Opcode::BNE => {
                    self.is_bne = F::one();
                }
                Opcode::BLT => {
                    self.is_blt = F::one();
                }
                Opcode::BGE => {
                    self.is_bge = F::one();
                }
                Opcode::BLTU => {
                    self.is_bltu = F::one();
                }
                Opcode::BGEU => {
                    self.is_bgeu = F::one();
                }
                _ => unreachable!(),
            }
        } else if instruction.opcode == Opcode::JAL {
            self.jal = F::one();
        } else if instruction.opcode == Opcode::JALR {
            self.jalr = F::one();
        } else if instruction.opcode == Opcode::UNIMP {
            self.noop = F::one();
        }

        if instruction.op_a == 0 {
            // If op_a is 0 and we're writing to the register, then we don't do a write.
            // We are always writing to the first register UNLESS it is a branch, is_store.
            if !(instruction.is_branch_instruction()
                || self.is_store == F::one()
                || self.noop == F::one())
            {
                self.reg_0_write = F::one();
            }
        }
    }
}

pub trait InstructionType<AB: AirBuilder> {
    fn is_branch_instruction(&self) -> AB::Expr;

    fn is_alu_instruction(&self) -> AB::Expr;

    fn is_memory_instruction(&self) -> AB::Expr;
}

impl<AB: AirBuilder> InstructionType<AB> for OpcodeSelectors<AB::Var> {
    fn is_branch_instruction(&self) -> AB::Expr {
        self.is_beq + self.is_bne + self.is_blt + self.is_bge + self.is_bltu + self.is_bgeu
    }

    fn is_alu_instruction(&self) -> AB::Expr {
        self.add_op
            + self.sub_op
            + self.mul_op
            + self.div_op
            + self.shift_op
            + self.bitwise_op
            + self.lt_op
    }

    fn is_memory_instruction(&self) -> AB::Expr {
        self.is_load + self.is_store
    }
}
