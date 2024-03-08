mod instruction;
mod opcode;
mod program;
mod record;

use std::sync::Arc;

pub use instruction::*;
pub use opcode::*;
pub use program::*;
pub use record::*;

use crate::cpu::CpuEvent;
use p3_field::PrimeField32;

pub struct Runtime<F: PrimeField32 + Clone> {
    /// The current clock.
    pub clk: F,

    /// The frame pointer.
    pub fp: F,

    /// The program counter.
    pub pc: F,

    /// The program.
    pub program: Program<F>,

    /// Memory.
    pub memory: Vec<F>,

    /// The execution record.
    pub record: ExecutionRecord<F>,
}

impl<F: PrimeField32 + Clone> Runtime<F> {
    pub fn new(program: &Program<F>) -> Self {
        let record = ExecutionRecord::<F> {
            program: Arc::new(program.clone()),
            ..Default::default()
        };
        Self {
            clk: F::zero(),
            program: program.clone(),
            fp: F::zero(),
            pc: F::zero(),
            memory: vec![F::zero(); 1024 * 1024],
            record,
        }
    }

    /// Fetch the destination address and input operand values for an ALU instruction.
    fn alu_rr(&mut self, instruction: &Instruction<F>) -> (F, F, F) {
        if !instruction.imm_c {
            let a_ptr = self.fp + instruction.op_a;
            let b_val = self.memory[(self.fp + instruction.op_b).as_canonical_u32() as usize];
            let c_val = self.memory[(self.fp + instruction.op_c).as_canonical_u32() as usize];
            (a_ptr, b_val, c_val)
        } else {
            let a_ptr = self.fp + instruction.op_a;
            let b_val = self.memory[(self.fp + instruction.op_b).as_canonical_u32() as usize];
            let c_val = instruction.op_c;
            (a_ptr, b_val, c_val)
        }
    }

    /// Fetch the destination address input operand values for a load instruction (from heap).
    fn load_rr(&mut self, instruction: &Instruction<F>) -> (F, F) {
        if !instruction.imm_b {
            let a_ptr = self.fp + instruction.op_a;
            let b_ptr = self.memory[(self.fp + instruction.op_b).as_canonical_u32() as usize];
            let b = self.memory[(b_ptr).as_canonical_u32() as usize];
            (a_ptr, b)
        } else {
            let a_ptr = self.fp + instruction.op_a;
            (a_ptr, instruction.op_b)
        }
    }

    /// Fetch the destination address input operand values for a store instruction (from stack).
    fn store_rr(&mut self, instruction: &Instruction<F>) -> (F, F) {
        if !instruction.imm_b {
            let a_ptr = self.fp + instruction.op_a;
            let b = self.memory[(self.fp + instruction.op_b).as_canonical_u32() as usize];
            (a_ptr, b)
        } else {
            let a_ptr = self.fp + instruction.op_a;
            (a_ptr, instruction.op_b)
        }
    }

    /// Fetch the input operand values for a branch instruction.
    fn branch_rr(&mut self, instruction: &Instruction<F>) -> (F, F, F) {
        let a = self.memory[(self.fp + instruction.op_a).as_canonical_u32() as usize];
        let b = if !instruction.imm_b {
            self.memory[(self.fp + instruction.op_b).as_canonical_u32() as usize]
        } else {
            instruction.op_b
        };
        let c = instruction.op_c;
        (a, b, c)
    }

    pub fn run(&mut self) {
        while self.pc < F::from_canonical_u32(self.program.instructions.len() as u32) {
            let idx = self.pc.as_canonical_u32() as usize;
            let instruction = self.program.instructions[idx].clone();
            let mut next_pc = self.pc + F::one();
            let (a, b, c): (F, F, F);
            match instruction.opcode {
                Opcode::ADD => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = b_val + c_val;
                    self.memory[(a_ptr).as_canonical_u32() as usize] = a_val;
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::SUB => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = b_val - c_val;
                    self.memory[(a_ptr).as_canonical_u32() as usize] = a_val;
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::MUL => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = b_val * c_val;
                    self.memory[(a_ptr).as_canonical_u32() as usize] = a_val;
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::DIV => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = b_val / c_val;
                    self.memory[(a_ptr).as_canonical_u32() as usize] = a_val;
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::LW => {
                    let (a_ptr, b_val) = self.load_rr(&instruction);
                    let a_val = b_val;
                    self.memory[(a_ptr).as_canonical_u32() as usize] = a_val;
                    (a, b, c) = (a_val, b_val, F::zero());
                }
                Opcode::SW => {
                    let (a_ptr, b_val) = self.store_rr(&instruction);
                    let a_val = b_val;
                    self.memory[(a_ptr).as_canonical_u32() as usize] = a_val;
                    (a, b, c) = (a_val, b_val, F::zero());
                }
                Opcode::BEQ => {
                    (a, b, c) = self.branch_rr(&instruction);
                    if a == b {
                        next_pc = c;
                    }
                }
                Opcode::BNE => {
                    (a, b, c) = self.branch_rr(&instruction);
                    if a != b {
                        next_pc = c;
                    }
                }
                Opcode::JAL => {
                    let imm = instruction.op_b;
                    let a_ptr = instruction.op_a + self.fp;
                    self.memory[(a_ptr).as_canonical_u32() as usize] = self.pc;
                    next_pc = self.pc + imm;
                    (a, b, c) = (a_ptr, F::zero(), F::zero());
                }
                Opcode::JALR => {
                    let imm = instruction.op_c;
                    let b_ptr = instruction.op_b + self.fp;
                    let a_ptr = instruction.op_a + self.fp;
                    let b_val = self.memory[(b_ptr).as_canonical_u32() as usize];
                    let c_val = imm;
                    let a_val = self.pc + F::one();
                    self.memory[(a_ptr).as_canonical_u32() as usize] = a_val;
                    next_pc = b_val + c_val;
                    (a, b, c) = (a_val, b_val, c_val);
                }
            };

            let event = CpuEvent {
                clk: self.clk,
                pc: self.pc,
                fp: self.fp,
                instruction: instruction.clone(),
                a,
                a_record: None,
                b,
                b_record: None,
                c,
                c_record: None,
            };
            self.pc = next_pc;
            self.record.cpu_events.push(event);
            self.clk += F::one();
        }
    }
}
