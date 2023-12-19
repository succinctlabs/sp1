use crate::runtime::{Instruction, Opcode};
use core::borrow::{Borrow, BorrowMut};
use p3_field::PrimeField;
use valida_derive::AlignedBorrow;

#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
pub struct OpcodeSelectors<T> {
    // // Whether op_b is an immediate value.
    pub imm_b: T,
    // Whether op_c is an immediate value.
    pub imm_c: T,

    // Table selectors for opcodes.
    pub add_op: T,
    pub sub_op: T,
    pub mul_op: T,
    pub div_op: T,
    pub shift_op: T,
    pub bitwise_op: T,
    pub lt_op: T,

    // Memory operation selectors.
    pub is_load: T,
    pub is_store: T,
    pub is_word: T,
    pub is_half: T,
    pub is_byte: T,
    pub is_signed: T,

    // Whether this is a precompile that requires a lookup.
    pub is_lookup_precompile: T,

    // Specific instruction selectors.
    pub jalr: T,
    pub jal: T,
    pub auipc: T,

    // Whether this is a branch op.
    pub branch_op: T,

    // Whether this is a no-op.
    pub noop: T,
    pub reg_0_write: T,
}

impl<F: PrimeField> OpcodeSelectors<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        match instruction.opcode {
            // Register instructions
            Opcode::ADD
            | Opcode::SUB
            | Opcode::XOR
            | Opcode::OR
            | Opcode::AND
            | Opcode::SLL
            | Opcode::SRL
            | Opcode::SRA
            | Opcode::SLT
            | Opcode::SLTU => {
                // For register instructions, neither imm_b or imm_c should be turned on.
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
                    Opcode::SLL | Opcode::SRL => {
                        self.shift_op = F::one();
                    }
                    Opcode::SLT | Opcode::SLTU => {
                        self.lt_op = F::one();
                    }
                    Opcode::SRA => {
                        panic!("SRA not implemented");
                    }
                    _ => {
                        panic!("unexpected opcode in register instruction table processing.")
                    }
                }
            }
            // Immediate instructions
            Opcode::ADDI
            | Opcode::XORI
            | Opcode::ORI
            | Opcode::ANDI
            | Opcode::SLLI
            | Opcode::SRLI
            | Opcode::SRAI
            | Opcode::SLTI
            | Opcode::SLTIU => {
                // For immediate instructions, imm_c should be turned on.
                self.imm_c = F::one();
                match instruction.opcode {
                    Opcode::ADDI => {
                        self.add_op = F::one();
                    }
                    Opcode::XORI | Opcode::ORI | Opcode::ANDI => {
                        self.bitwise_op = F::one();
                    }
                    Opcode::SLLI | Opcode::SRLI => {
                        self.shift_op = F::one();
                    }
                    Opcode::SLTI | Opcode::SLTIU => {
                        self.lt_op = F::one();
                    }
                    Opcode::SRAI => {
                        panic!("SRAI not implemented");
                    }
                    _ => {
                        panic!("unexpected opcode in immediate instruction table processing.")
                    }
                }
            }
            // Load instructions
            Opcode::LB | Opcode::LH | Opcode::LW | Opcode::LBU | Opcode::LHU => {
                // For load instructions, imm_c should be turned on.
                self.imm_c = F::one();
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
                    _ => {
                        panic!("unexpected opcode in load instruction table processing.")
                    }
                }
            }
            // Store instructions
            Opcode::SB | Opcode::SH | Opcode::SW => {
                // For store instructions, imm_c should be turned on, but mem_read stays off.
                self.imm_c = F::one();
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
                    _ => {
                        panic!("unexpected opcode in store instruction table processing.")
                    }
                }
            }
            // Branch instructions
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                self.imm_c = F::one();
                self.branch_op = F::one();
            }
            // Jump instructions
            Opcode::JAL => {
                self.jal = F::one();
                self.imm_b = F::one();
                self.imm_c = F::one();
            }
            Opcode::JALR => {
                self.jalr = F::one();
                self.imm_c = F::one();
            }
            // Upper immediate instructions
            Opcode::LUI => {
                // Note that we convert a LUI opcode to a SLL opcode with both imm_b and imm_c turned on.
                // And the value of imm_c is 12.
                self.imm_b = F::one();
                self.imm_c = F::one();
                // In order to process lookups for the SLL opcode table, we'll also turn on the "shift_op".
                self.shift_op = F::one();
            }
            Opcode::AUIPC => {
                // Note that for an AUIPC opcode, we turn on both imm_b and imm_c.
                self.imm_b = F::one();
                self.imm_c = F::one();
                self.auipc = F::one();
                // We constraint that imm_c = imm_b << 12 by looking up SLL(op_c_val, op_b_val, 12) with multiplicity AUIPC.
                // Then we constraint op_a_val = op_c_val + pc by looking up ADD(op_a_val, op_c_val, pc) with multiplicity AUIPC.
            }
            // Multiply instructions
            Opcode::MUL
            | Opcode::MULH
            | Opcode::MULHSU
            | Opcode::MULHU
            | Opcode::DIV
            | Opcode::DIVU
            | Opcode::REM
            | Opcode::REMU => {
                self.mul_op = F::one();
            }
            Opcode::UNIMP => {
                self.noop = F::one();
                // So that we don't read from the registers for these instructions.
                self.imm_b = F::one();
                self.imm_c = F::one();
            }
            Opcode::ECALL => {
                // TODO: set is_lookup_precompile to true
                self.imm_c = F::one();
            }
            _ => panic!("Invalid opcode {:?}", instruction.opcode),
        }
        if instruction.op_a == 0 {
            // If op_a is 0 and we're writing to the register, then we don't do a write.
            // We are always writing to the first register UNLESS it is a branch, is_store.
            if !(self.branch_op == F::one() || self.is_store == F::one() || self.noop == F::one()) {
                self.reg_0_write = F::one();
            }
        }
    }
}
