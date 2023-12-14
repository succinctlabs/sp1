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

    // Memory operation
    pub mem_op: T,
    pub mem_read: T,

    // Specific instruction selectors.
    pub jalr: T,
    pub jal: T,
    pub auipc: T,

    // Whether this is a branch op.
    pub branch_op: T,

    // Whether this is a no-op.
    pub noop: T,
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
                self.mem_op = F::one();
                self.mem_read = F::one();
            }
            // Store instructions
            Opcode::SB | Opcode::SH | Opcode::SW => {
                // For store instructions, imm_c should be turned on, but mem_read stays off.
                self.imm_c = F::one();
                self.mem_op = F::one();
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
            _ => panic!("Invalid opcode"),
        }
    }
}
