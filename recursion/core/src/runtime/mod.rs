mod instruction;
mod opcode;
mod program;
mod record;

use crate::memory::MemoryRecord;
use std::sync::Arc;

pub use instruction::*;
pub use opcode::*;
pub use program::*;
pub use record::*;
use sp1_core::runtime::AccessPosition;

use crate::cpu::CpuEvent;
use p3_field::PrimeField32;

#[derive(Debug, Clone, Default)]
pub struct CpuRecord<F> {
    pub a: Option<MemoryRecord<F>>,
    pub b: Option<MemoryRecord<F>>,
    pub c: Option<MemoryRecord<F>>,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryEntry<F: PrimeField32> {
    pub value: F,
    pub timestamp: F,
}

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
    pub memory: Vec<MemoryEntry<F>>,

    /// The execution record.
    pub record: ExecutionRecord<F>,

    pub access: CpuRecord<F>,
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
            fp: F::from_canonical_usize(1024),
            pc: F::zero(),
            memory: vec![MemoryEntry::default(); 1024 * 1024],
            record,
            access: CpuRecord::default(),
        }
    }

    fn mr(&mut self, addr: F, position: AccessPosition) -> F {
        let entry = self.memory[addr.as_canonical_u32() as usize].clone();
        let (prev_value, prev_timestamp) = (entry.value, entry.timestamp);
        let record = MemoryRecord {
            addr,
            value: prev_value,
            timestamp: self.timestamp(&position),
            prev_value,
            prev_timestamp,
        };
        match position {
            AccessPosition::A => self.access.a = Some(record),
            AccessPosition::B => self.access.b = Some(record),
            AccessPosition::C => self.access.c = Some(record),
            _ => unreachable!(),
        };
        prev_value
    }

    fn mw(&mut self, addr: F, value: F, position: AccessPosition) {
        let entry = self.memory[addr.as_canonical_u32() as usize].clone();
        let (prev_value, prev_timestamp) = (entry.value, entry.timestamp);
        let timestamp = self.timestamp(&position);
        let record = MemoryRecord {
            addr,
            value: prev_value,
            timestamp,
            prev_value,
            prev_timestamp,
        };
        self.memory[addr.as_canonical_u32() as usize] = MemoryEntry { value, timestamp };
        match position {
            AccessPosition::A => self.access.a = Some(record),
            AccessPosition::B => self.access.b = Some(record),
            AccessPosition::C => self.access.c = Some(record),
            _ => unreachable!(),
        };
    }

    fn timestamp(&self, position: &AccessPosition) -> F {
        self.clk + F::from_canonical_u32(*position as u32)
    }

    /// Fetch the destination address and input operand values for an ALU instruction.
    fn alu_rr(&mut self, instruction: &Instruction<F>) -> (F, F, F) {
        let a_ptr = self.fp + instruction.op_a;
        let c_val = if !instruction.imm_c {
            self.mr(self.fp + instruction.op_c, AccessPosition::C)
        } else {
            instruction.op_c
        };
        let b_val = if !instruction.imm_b {
            self.mr(self.fp + instruction.op_b, AccessPosition::B)
        } else {
            instruction.op_b
        };
        (a_ptr, b_val, c_val)
    }

    /// Fetch the destination address input operand values for a load instruction (from heap).
    fn load_rr(&mut self, instruction: &Instruction<F>) -> (F, F) {
        if !instruction.imm_b {
            let a_ptr = self.fp + instruction.op_a;
            let b = self.mr(self.fp + instruction.op_b, AccessPosition::B);
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
            let b = self.mr(self.fp + instruction.op_b, AccessPosition::B);
            (a_ptr, b)
        } else {
            let a_ptr = self.fp + instruction.op_a;
            (a_ptr, instruction.op_b)
        }
    }

    /// Fetch the input operand values for a branch instruction.
    fn branch_rr(&mut self, instruction: &Instruction<F>) -> (F, F, F) {
        let a = self.mr(self.fp + instruction.op_a, AccessPosition::A);
        let b = if !instruction.imm_b {
            self.mr(self.fp + instruction.op_b, AccessPosition::B)
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
                    self.mw(a_ptr, a_val, AccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::SUB => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = b_val - c_val;
                    self.mw(a_ptr, a_val, AccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::MUL => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = b_val * c_val;
                    self.mw(a_ptr, a_val, AccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::DIV => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = b_val / c_val;
                    self.mw(a_ptr, a_val, AccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::LW => {
                    let (a_ptr, b_val) = self.load_rr(&instruction);
                    let a_val = b_val;
                    self.mw(a_ptr, a_val, AccessPosition::A);
                    (a, b, c) = (a_val, b_val, F::zero());
                }
                Opcode::SW => {
                    let (a_ptr, b_val) = self.store_rr(&instruction);
                    let a_val = b_val;
                    self.mw(a_ptr, a_val, AccessPosition::A);
                    (a, b, c) = (a_val, b_val, F::zero());
                }
                Opcode::BEQ => {
                    (a, b, c) = self.branch_rr(&instruction);
                    if a == b {
                        next_pc = self.pc + c;
                    }
                }
                Opcode::BNE => {
                    (a, b, c) = self.branch_rr(&instruction);
                    if a != b {
                        next_pc = self.pc + c;
                    }
                }
                Opcode::JAL => {
                    let imm = instruction.op_b;
                    let a_ptr = instruction.op_a + self.fp;
                    self.mw(a_ptr, self.pc, AccessPosition::A);
                    next_pc = self.pc + imm;
                    self.fp += instruction.op_c;
                    (a, b, c) = (a_ptr, F::zero(), F::zero());
                }
                Opcode::JALR => {
                    let imm = instruction.op_c;
                    let b_ptr = instruction.op_b + self.fp;
                    let a_ptr = instruction.op_a + self.fp;
                    let b_val = self.mr(b_ptr, AccessPosition::B);
                    let c_val = imm;
                    let a_val = self.pc + F::one();
                    self.mw(a_ptr, a_val, AccessPosition::A);
                    next_pc = b_val;
                    self.fp = c_val;
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::TRAP => {
                    panic!("TRAP instruction encountered")
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
