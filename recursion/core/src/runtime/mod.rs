mod instruction;
mod opcode;
mod program;
mod record;

use std::{marker::PhantomData, sync::Arc};

pub use instruction::*;
pub use opcode::*;
pub use program::*;
pub use record::*;

use crate::cpu::CpuEvent;
use crate::memory::MemoryRecord;
use crate::poseidon2::Poseidon2Event;
use crate::{air::Block, poseidon2::WIDTH};

use p3_field::{ExtensionField, PrimeField32};
use sp1_core::runtime::MemoryAccessPosition;

pub const STACK_SIZE: usize = 1 << 20;
pub const MEMORY_SIZE: usize = 1 << 26;

pub const D: usize = 4;

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

pub struct Runtime<F: PrimeField32, EF: ExtensionField<F>> {
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

    _marker: PhantomData<EF>,
}

impl<F: PrimeField32, EF: ExtensionField<F>> Runtime<F, EF> {
    pub fn new(program: &Program<F>) -> Self {
        let record = ExecutionRecord::<F> {
            program: Arc::new(program.clone()),
            ..Default::default()
        };
        Self {
            clk: F::zero(),
            program: program.clone(),
            fp: F::from_canonical_usize(STACK_SIZE),
            pc: F::zero(),
            memory: vec![MemoryEntry::default(); MEMORY_SIZE],
            record,
            access: CpuRecord::default(),
            _marker: PhantomData,
        }
    }

    fn mr(&mut self, addr: F, position: MemoryAccessPosition) -> (MemoryRecord<F>, Block<F>) {
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
            MemoryAccessPosition::A => self.access.a = Some(record.clone()),
            MemoryAccessPosition::B => self.access.b = Some(record.clone()),
            MemoryAccessPosition::C => self.access.c = Some(record.clone()),
            _ => unreachable!(),
        };
        (record, prev_value)
    }

    fn mw(&mut self, addr: F, value: Block<F>, position: MemoryAccessPosition) -> MemoryRecord<F> {
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
            MemoryAccessPosition::A => self.access.a = Some(record.clone()),
            MemoryAccessPosition::B => self.access.b = Some(record.clone()),
            MemoryAccessPosition::C => self.access.c = Some(record.clone()),
            _ => unreachable!(),
        };

        record
    }

    fn timestamp(&self, position: &MemoryAccessPosition) -> F {
        self.clk + F::from_canonical_u32(*position as u32)
    }

    fn get_b(&mut self, instruction: &Instruction<F>) -> Block<F> {
        if instruction.imm_b_base() {
            Block::from(instruction.op_b[0])
        } else if instruction.imm_b {
            instruction.op_b
        } else {
            let (_, value) = self.mr(self.fp + instruction.op_b[0], MemoryAccessPosition::B);
            value
        }
    }

    fn get_c(&mut self, instruction: &Instruction<F>) -> Block<F> {
        if instruction.imm_c_base() {
            Block::from(instruction.op_c[0])
        } else if instruction.imm_c {
            instruction.op_c
        } else {
            let (_, value) = self.mr(self.fp + instruction.op_c[0], MemoryAccessPosition::C);
            value
        }
    }

    /// Fetch the destination address and input operand values for an ALU instruction.
    fn alu_rr(&mut self, instruction: &Instruction<F>) -> (F, Block<F>, Block<F>) {
        let a_ptr = self.fp + instruction.op_a;
        let c_val = self.get_c(instruction);
        let b_val = self.get_b(instruction);

        (a_ptr, b_val, c_val)
    }

    /// Fetch the destination address input operand values for a load instruction (from heap).
    fn load_rr(&mut self, instruction: &Instruction<F>) -> (F, Block<F>) {
        let a_ptr = self.fp + instruction.op_a;
        let b = if instruction.imm_b_base() {
            Block::from(instruction.op_b[0])
        } else if instruction.imm_b {
            instruction.op_b
        } else {
            let address = self.mr(self.fp + instruction.op_b[0], MemoryAccessPosition::B);
            let (_, value) = self.mr(address.1[0], MemoryAccessPosition::A);
            value
        };
        (a_ptr, b)
    }

    /// Fetch the destination address input operand values for a store instruction (from stack).
    fn store_rr(&mut self, instruction: &Instruction<F>) -> (F, Block<F>) {
        let a_ptr = if instruction.imm_b {
            self.fp + instruction.op_a
        } else {
            let (_, value) = self.mr(self.fp + instruction.op_a, MemoryAccessPosition::A);
            value[0]
        };
        let b = if instruction.imm_b_base() {
            Block::from(instruction.op_b[0])
        } else if instruction.imm_b {
            instruction.op_b
        } else {
            let (_, value) = self.mr(self.fp + instruction.op_b[0], MemoryAccessPosition::B);
            value
        };
        (a_ptr, b)
    }

    /// Fetch the input operand values for a branch instruction.
    fn branch_rr(&mut self, instruction: &Instruction<F>) -> (Block<F>, Block<F>, F) {
        let (_, a) = self.mr(self.fp + instruction.op_a, MemoryAccessPosition::A);
        let b = self.get_b(instruction);

        let c = instruction.op_c[0];
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
                Opcode::EADD | Opcode::EFADD => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let sum = EF::from_base_slice(&b_val.0) + EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(sum.as_base_slice());
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::EMUL | Opcode::EFMUL => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let product = EF::from_base_slice(&b_val.0) * EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(product.as_base_slice());
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::ESUB | Opcode::EFSUB => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let diff = EF::from_base_slice(&b_val.0) - EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(diff.as_base_slice());
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::EDIV | Opcode::EFDIV => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let quotient = EF::from_base_slice(&b_val.0) / EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(quotient.as_base_slice());
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::LW => {
                    let (a_ptr, b_val) = self.load_rr(&instruction);
                    let (_, prev_a) = self.mr(a_ptr, MemoryAccessPosition::A);
                    let a_val = Block::from([b_val[0], prev_a[1], prev_a[2], prev_a[3]]);
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, Block::default());
                }
                Opcode::LE => {
                    let (a_ptr, b_val) = self.load_rr(&instruction);
                    let a_val = b_val;
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, Block::default());
                }
                Opcode::SW => {
                    let (a_ptr, b_val) = self.store_rr(&instruction);
                    let (_, prev_a) = self.mr(a_ptr, MemoryAccessPosition::A);
                    let a_val = Block::from([b_val[0], prev_a[1], prev_a[2], prev_a[3]]);
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, Block::default());
                }
                Opcode::SE => {
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
                Opcode::EBEQ => {
                    let (a_val, b_val, c_offset) = self.branch_rr(&instruction);
                    (a, b, c) = (a_val, b_val, Block::from(c_offset));
                    if a == b {
                        next_pc = self.pc + c_offset;
                    }
                }
                Opcode::EBNE => {
                    let (a_val, b_val, c_offset) = self.branch_rr(&instruction);
                    (a, b, c) = (a_val, b_val, Block::from(c_offset));
                    if a != b {
                        next_pc = self.pc + c_offset;
                    }
                }
                Opcode::JAL => {
                    let imm = instruction.op_b[0];
                    let a_ptr = instruction.op_a + self.fp;
                    self.mw(a_ptr, Block::from(self.pc), MemoryAccessPosition::A);
                    next_pc = self.pc + imm;
                    self.fp += instruction.op_c[0];
                    (a, b, c) = (Block::from(a_ptr), Block::default(), Block::default());
                }
                Opcode::JALR => {
                    let imm = instruction.op_c;
                    let b_ptr = instruction.op_b[0] + self.fp;
                    let a_ptr = instruction.op_a + self.fp;
                    let (_, b_val) = self.mr(b_ptr, MemoryAccessPosition::B);
                    let c_val = imm;
                    let a_val = Block::from(self.pc + F::one());
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    next_pc = b_val.0[0];
                    self.fp = c_val[0];
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::TRAP => {
                    panic!("TRAP instruction encountered")
                }
                Opcode::POSEIDON2 => {
                    let state_ptr = self.fp + instruction.op_a;

                    let mut memory_records = vec![];
                    let mut read_records: Vec<MemoryRecord<F>> = vec![];

                    for i in 0..32 {
                        if i == 0 {
                            let read_records = (0..WIDTH / 4)
                                .map(|i| {
                                    let addr = state_ptr + F::from_canonical_u32(i as u32 * 4);
                                    let (record, _) = self.mr(addr, MemoryAccessPosition::A);
                                    record
                                })
                                .collect::<Vec<_>>();

                            memory_records.extend(read_records.clone());
                        }

                        // input state
                        let state: [F; WIDTH] = read_records
                            .iter()
                            .take(WIDTH / 4)
                            .flat_map(|block| block.value.0)
                            .collect::<Vec<_>>()
                            .try_into()
                            .unwrap();

                        // let poseidon2 = Poseidon2::new(
                        //     ROUNDS_F,
                        //     ROUNDS_P,
                        //     RC_16_30.to_vec(),
                        //     DiffusionMatrixBabybear,
                        // );

                        // perform one round of poseidon2
                        // poseidon2.permute_mut(&mut state);

                        let output = state.clone();

                        // Update the memory with the output of the last round
                        let write_records = (0..WIDTH / 4)
                            .map(|i| {
                                let addr = state_ptr + F::from_canonical_u32(i as u32 * 4);
                                let out = [
                                    output[i * 4],
                                    output[i * 4 + 1],
                                    output[i * 4 + 2],
                                    output[i * 4 + 3],
                                ];
                                let value = Block::from(out);
                                self.mw(addr, value, MemoryAccessPosition::A)
                            })
                            .collect::<Vec<_>>();

                        memory_records.extend(write_records.clone());

                        read_records = write_records.clone();
                    }

                    let poseidon2_event = Poseidon2Event {
                        state_ptr,
                        clk: self.clk,
                        state_read_records: memory_records,
                    };

                    self.record.poseidon2_events.push(poseidon2_event);

                    (a, b, c) = (
                        Block::from([state_ptr, F::zero(), F::zero(), F::zero()]),
                        Block::default(),
                        Block::default(),
                    );
                }
            }

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
