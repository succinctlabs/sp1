mod instruction;
mod opcode;
mod program;
mod record;

use std::sync::Arc;

pub use instruction::*;
pub use opcode::*;
pub use program::*;
pub use record::*;

use crate::air::Block;
use crate::cpu::CpuEvent;
use crate::memory::MemoryRecord;

use p3_field::PrimeField32;
use sp1_core::runtime::MemoryAccessPosition;

#[derive(Debug, Clone, Default)]
pub struct CpuRecord<F> {
    pub a: Option<MemoryRecord<F>>,
    pub b: Option<MemoryRecord<F>>,
    pub c: Option<MemoryRecord<F>>,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryEntry<F: PrimeField32> {
    pub value: Block<F>,
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

    /// The access record for this cycle.
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

    fn mr(&mut self, addr: F, position: MemoryAccessPosition) -> Block<F> {
        let addr_usize = addr.as_canonical_u32() as usize;
        let entry = self.memory[addr.as_canonical_u32() as usize].clone();
        let (prev_value, prev_timestamp) = (entry.value, entry.timestamp);
        let record = MemoryRecord {
            addr,
            value: prev_value,
            timestamp: self.timestamp(&position),
            prev_value,
            prev_timestamp,
        };
        self.memory[addr_usize] = MemoryEntry {
            value: prev_value,
            timestamp: self.timestamp(&position),
        };
        match position {
            MemoryAccessPosition::A => self.access.a = Some(record),
            MemoryAccessPosition::B => self.access.b = Some(record),
            MemoryAccessPosition::C => self.access.c = Some(record),
            _ => unreachable!(),
        };
        prev_value
    }

    fn mw(&mut self, addr: F, value: Block<F>, position: MemoryAccessPosition) {
        let addr_usize = addr.as_canonical_u32() as usize;
        let timestamp = self.timestamp(&position);
        let entry = &self.memory[addr_usize];
        let (prev_value, prev_timestamp) = (entry.value, entry.timestamp);
        let record = MemoryRecord {
            addr,
            value,
            timestamp,
            prev_value,
            prev_timestamp,
        };
        self.memory[addr_usize] = MemoryEntry { value, timestamp };
        match position {
            MemoryAccessPosition::A => self.access.a = Some(record),
            MemoryAccessPosition::B => self.access.b = Some(record),
            MemoryAccessPosition::C => self.access.c = Some(record),
            _ => unreachable!(),
        };
    }

    fn timestamp(&self, position: &MemoryAccessPosition) -> F {
        self.clk + F::from_canonical_u32(*position as u32)
    }

    /// Fetch the destination address and input operand values for an ALU instruction.
    fn alu_rr(&mut self, instruction: &Instruction<F>) -> (F, Block<F>, Block<F>) {
        let a_ptr = self.fp + instruction.op_a;
        let c_val = if !instruction.imm_c {
            self.mr(self.fp + instruction.op_c, MemoryAccessPosition::C)
        } else {
            Block::from(instruction.op_c)
        };
        let b_val = if !instruction.imm_b {
            self.mr(self.fp + instruction.op_b, MemoryAccessPosition::B)
        } else {
            Block::from(instruction.op_b)
        };
        (a_ptr, b_val, c_val)
    }

    /// Fetch the destination address input operand values for a load instruction (from heap).
    fn load_rr(&mut self, instruction: &Instruction<F>) -> (F, Block<F>) {
        if !instruction.imm_b {
            let a_ptr = self.fp + instruction.op_a;
            let b = self.mr(self.fp + instruction.op_b, MemoryAccessPosition::B);
            (a_ptr, b)
        } else {
            let a_ptr = self.fp + instruction.op_a;
            let b = Block::from(instruction.op_b);
            (a_ptr, b)
        }
    }

    /// Fetch the destination address input operand values for a store instruction (from stack).
    fn store_rr(&mut self, instruction: &Instruction<F>) -> (F, Block<F>) {
        if !instruction.imm_b {
            let a_ptr = self.fp + instruction.op_a;
            let b = self.mr(self.fp + instruction.op_b, MemoryAccessPosition::B);
            (a_ptr, b)
        } else {
            let a_ptr = self.fp + instruction.op_a;
            (a_ptr, Block::from(instruction.op_b))
        }
    }

    /// Fetch the input operand values for a branch instruction.
    fn branch_rr(&mut self, instruction: &Instruction<F>) -> (Block<F>, Block<F>, F) {
        let a = self.mr(self.fp + instruction.op_a, MemoryAccessPosition::A);
        let b = if !instruction.imm_b {
            self.mr(self.fp + instruction.op_b, MemoryAccessPosition::B)
        } else {
            Block::from(instruction.op_b)
        };
        let c = instruction.op_c;
        (a, b, c)
    }

    pub fn run(&mut self) {
        while self.pc < F::from_canonical_u32(self.program.instructions.len() as u32) {
            let idx = self.pc.as_canonical_u32() as usize;
            let instruction = self.program.instructions[idx].clone();
            let mut next_pc = self.pc + F::one();
            let (a, b, c): (Block<F>, Block<F>, Block<F>);
            match instruction.opcode {
                Opcode::ADD => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val.0[0] = b_val.0[0] + c_val.0[0];
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::SUB => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val.0[0] = b_val.0[0] - c_val.0[0];
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::MUL => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val.0[0] = b_val.0[0] * c_val.0[0];
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::DIV => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val.0[0] = b_val.0[0] / c_val.0[0];
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::LW => {
                    let (a_ptr, b_val) = self.load_rr(&instruction);
                    let a_val = b_val;
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, Block::default());
                }
                Opcode::SW => {
                    let (a_ptr, b_val) = self.store_rr(&instruction);
                    let a_val = b_val;
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, Block::default());
                }
                Opcode::BEQ => {
                    let (a_val, b_val, c_offset) = self.branch_rr(&instruction);
                    (a, b, c) = (a_val, b_val, Block::from(c_offset));
                    if a.0[0] == b.0[0] {
                        next_pc = self.pc + c_offset;
                    }
                }
                Opcode::BNE => {
                    let (a_val, b_val, c_offset) = self.branch_rr(&instruction);
                    (a, b, c) = (a_val, b_val, Block::from(c_offset));
                    if a.0[0] != b.0[0] {
                        next_pc = self.pc + c_offset;
                    }
                }
                Opcode::JAL => {
                    let imm = instruction.op_b;
                    let a_ptr = instruction.op_a + self.fp;
                    self.mw(a_ptr, Block::from(self.pc), MemoryAccessPosition::A);
                    next_pc = self.pc + imm;
                    self.fp += instruction.op_c;
                    (a, b, c) = (Block::from(a_ptr), Block::default(), Block::default());
                }
                Opcode::JALR => {
                    let imm = instruction.op_c;
                    let b_ptr = instruction.op_b + self.fp;
                    let a_ptr = instruction.op_a + self.fp;
                    let b_val = self.mr(b_ptr, MemoryAccessPosition::B);
                    let c_val = imm;
                    let a_val = Block::from(self.pc + F::one());
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    next_pc = b_val.0[0];
                    self.fp = c_val;
                    (a, b, c) = (a_val, b_val, Block::from(c_val));
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
                a_record: self.access.a.clone(),
                b,
                b_record: self.access.b.clone(),
                c,
                c_record: self.access.c.clone(),
            };
            self.pc = next_pc;
            self.record.cpu_events.push(event);
            self.clk += F::from_canonical_u32(4);
            self.access = CpuRecord::default();
        }

        // Collect all used memory addresses.
        for addr in 0..self.memory.len() {
            let entry = &self.memory[addr];
            if entry.timestamp != F::zero() {
                self.record
                    .first_memory_record
                    .push(F::from_canonical_usize(addr));
                self.record.last_memory_record.push((
                    F::from_canonical_usize(addr),
                    entry.timestamp,
                    entry.value,
                ))
            }
        }
    }
}
