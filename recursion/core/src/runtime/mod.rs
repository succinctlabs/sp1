mod instruction;
mod opcode;
mod program;
mod record;

use std::collections::VecDeque;
use std::process::exit;
use std::{marker::PhantomData, sync::Arc};

use hashbrown::HashMap;
pub use instruction::*;
use itertools::Itertools;
pub use opcode::*;
use p3_poseidon2::Poseidon2;
use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
use p3_symmetric::CryptographicPermutation;
use p3_symmetric::Permutation;
pub use program::*;
pub use record::*;

use crate::air::Block;
use crate::cpu::CpuEvent;
use crate::fri_fold::FriFoldEvent;
use crate::memory::MemoryRecord;
use crate::poseidon2::Poseidon2Event;

use p3_field::{ExtensionField, PrimeField32};
use sp1_core::runtime::MemoryAccessPosition;

pub const STACK_SIZE: usize = 1 << 24;
pub const MEMORY_SIZE: usize = 1 << 28;

/// The width of the Poseidon2 permutation.
pub const PERMUTATION_WIDTH: usize = 16;
pub const POSEIDON2_SBOX_DEGREE: u64 = 7;
pub const HASH_RATE: usize = 8;

/// The current verifier implementation assumes that we are using a 256-bit hash with 32-bit elements.
pub const DIGEST_SIZE: usize = 8;

/// The max size of the public values buffer
pub const PV_BUFFER_MAX_SIZE: usize = 1024;

pub const NUM_BITS: usize = 31;

pub const D: usize = 4;

#[derive(Debug, Clone, Default)]
pub struct CpuRecord<F> {
    pub a: Option<MemoryRecord<F>>,
    pub b: Option<MemoryRecord<F>>,
    pub c: Option<MemoryRecord<F>>,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryEntry<F> {
    pub value: Block<F>,
    pub timestamp: F,
}

#[derive(Debug, Clone, Default)]
pub struct CycleTrackerEntry {
    pub span_entered: bool,
    pub span_enter_cycle: usize,
    pub cumulative_cycles: usize,
}

pub struct Runtime<F: PrimeField32, EF: ExtensionField<F>, Diffusion> {
    pub timestamp: usize,

    pub nb_poseidons: usize,

    pub nb_bit_decompositions: usize,

    pub nb_ext_ops: usize,

    pub nb_base_ops: usize,

    pub nb_memory_ops: usize,

    pub nb_branch_ops: usize,

    pub nb_print_f: usize,

    pub nb_print_e: usize,

    /// The current clock.
    pub clk: F,

    /// The frame pointer.
    pub fp: F,

    /// The program counter.
    pub pc: F,

    /// The program.
    pub program: RecursionProgram<F>,

    /// Memory.
    // pub memory: Vec<MemoryEntry<F>>,
    pub memory: HashMap<usize, MemoryEntry<F>>,

    /// The execution record.
    pub record: ExecutionRecord<F>,

    /// The access record for this cycle.
    pub access: CpuRecord<F>,

    pub witness_stream: VecDeque<Vec<Block<F>>>,

    pub cycle_tracker: HashMap<String, CycleTrackerEntry>,

    // pub witness_stream: Vec<Witness<F, EF>>,
    perm: Option<
        Poseidon2<
            F,
            Poseidon2ExternalMatrixGeneral,
            Diffusion,
            PERMUTATION_WIDTH,
            POSEIDON2_SBOX_DEGREE,
        >,
    >,

    _marker: PhantomData<EF>,
}

impl<F: PrimeField32, EF: ExtensionField<F>, Diffusion> Runtime<F, EF, Diffusion>
where
    Poseidon2<
        F,
        Poseidon2ExternalMatrixGeneral,
        Diffusion,
        PERMUTATION_WIDTH,
        POSEIDON2_SBOX_DEGREE,
    >: CryptographicPermutation<[F; PERMUTATION_WIDTH]>,
{
    pub fn new(
        program: &RecursionProgram<F>,
        perm: Poseidon2<
            F,
            Poseidon2ExternalMatrixGeneral,
            Diffusion,
            PERMUTATION_WIDTH,
            POSEIDON2_SBOX_DEGREE,
        >,
    ) -> Self {
        let record = ExecutionRecord::<F> {
            program: Arc::new(program.clone()),
            ..Default::default()
        };
        Self {
            timestamp: 0,
            nb_poseidons: 0,
            nb_bit_decompositions: 0,
            nb_ext_ops: 0,
            nb_base_ops: 0,
            nb_memory_ops: 0,
            nb_branch_ops: 0,
            nb_print_f: 0,
            nb_print_e: 0,
            clk: F::zero(),
            program: program.clone(),
            fp: F::from_canonical_usize(STACK_SIZE),
            pc: F::zero(),
            memory: HashMap::new(),
            record,
            perm: Some(perm),
            access: CpuRecord::default(),
            witness_stream: VecDeque::new(),
            cycle_tracker: HashMap::new(),
            _marker: PhantomData,
        }
    }

    pub fn new_no_perm(program: &RecursionProgram<F>) -> Self {
        let record = ExecutionRecord::<F> {
            program: Arc::new(program.clone()),
            ..Default::default()
        };
        Self {
            timestamp: 0,
            nb_poseidons: 0,
            nb_bit_decompositions: 0,
            nb_ext_ops: 0,
            nb_base_ops: 0,
            nb_memory_ops: 0,
            nb_print_f: 0,
            nb_print_e: 0,
            nb_branch_ops: 0,
            clk: F::zero(),
            program: program.clone(),
            fp: F::from_canonical_usize(STACK_SIZE),
            pc: F::zero(),
            memory: HashMap::new(),
            record,
            perm: None,
            access: CpuRecord::default(),
            witness_stream: VecDeque::new(),
            cycle_tracker: HashMap::new(),
            _marker: PhantomData,
        }
    }

    pub fn print_stats(&self) {
        println!("Total Cycles: {}", self.timestamp);
        println!("Poseidon Operations: {}", self.nb_poseidons);
        println!("Field Operations: {}", self.nb_base_ops);
        println!("Extension Operations: {}", self.nb_ext_ops);
        println!("Memory Operations: {}", self.nb_memory_ops);
        println!("Branch Operations: {}", self.nb_branch_ops);
        println!("\nCycle Tracker Statistics:");
        for (name, entry) in self.cycle_tracker.iter().sorted_by_key(|(name, _)| *name) {
            println!("> {}: {}", name, entry.cumulative_cycles);
        }
    }

    fn mr_record(&mut self, addr: F, timestamp: F) -> (MemoryRecord<F>, Block<F>) {
        let entry = self
            .memory
            .entry(addr.as_canonical_u32() as usize)
            .or_default();
        let (prev_value, prev_timestamp) = (entry.value, entry.timestamp);
        let record = MemoryRecord::new_read(addr, prev_value, timestamp, prev_timestamp);
        *entry = MemoryEntry {
            value: prev_value,
            timestamp,
        };
        (record, prev_value)
    }

    fn mw_record(&mut self, addr: F, value: Block<F>, timestamp: F) -> MemoryRecord<F> {
        let addr_usize = addr.as_canonical_u32() as usize;
        let entry = self.memory.entry(addr_usize).or_default();
        let (prev_value, prev_timestamp) = (entry.value, entry.timestamp);
        let record = MemoryRecord::new_write(addr, value, timestamp, prev_value, prev_timestamp);
        *entry = MemoryEntry { value, timestamp };
        record
    }

    fn mr(&mut self, addr: F, position: MemoryAccessPosition) -> Block<F> {
        let timestamp = self.timestamp(&position);
        let (record, value) = self.mr_record(addr, timestamp);
        match position {
            MemoryAccessPosition::A => self.access.a = Some(record),
            MemoryAccessPosition::B => self.access.b = Some(record),
            MemoryAccessPosition::C => self.access.c = Some(record),
            _ => unreachable!(),
        };
        value
    }

    fn mw(&mut self, addr: F, value: Block<F>, position: MemoryAccessPosition) {
        let timestamp = self.timestamp(&position);
        let record = self.mw_record(addr, value, timestamp);
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

    fn get_b(&mut self, instruction: &Instruction<F>) -> Block<F> {
        if instruction.imm_b_base() {
            Block::from(instruction.op_b[0])
        } else if instruction.imm_b {
            instruction.op_b
        } else {
            self.mr(self.fp + instruction.op_b[0], MemoryAccessPosition::B)
        }
    }

    fn get_c(&mut self, instruction: &Instruction<F>) -> Block<F> {
        if instruction.imm_c_base() {
            Block::from(instruction.op_c[0])
        } else if instruction.imm_c {
            instruction.op_c
        } else {
            self.mr(self.fp + instruction.op_c[0], MemoryAccessPosition::C)
        }
    }

    /// Fetch the destination address and input operand values for an ALU instruction.
    fn alu_rr(&mut self, instruction: &Instruction<F>) -> (F, Block<F>, Block<F>) {
        let a_ptr = self.fp + instruction.op_a;
        let c_val = self.get_c(instruction);
        let b_val = self.get_b(instruction);

        (a_ptr, b_val, c_val)
    }

    /// Fetch the destination address input operand values for a store instruction (from stack).
    fn mem_rr(&mut self, instruction: &Instruction<F>) -> (F, Block<F>, Block<F>) {
        let a_ptr = self.fp + instruction.op_a;
        let c_val = self.get_c(instruction);
        let b_val = self.get_b(instruction);

        (a_ptr, b_val, c_val)
    }

    // A function to calculate the memory address for both load and store opcodes.
    fn calculate_address(b_val: Block<F>, c_val: Block<F>, instruction: &Instruction<F>) -> F {
        let index = c_val[0];
        let ptr = b_val[0];

        let offset = instruction.offset_imm;
        let size = instruction.size_imm;

        ptr + index * size + offset
    }

    /// Fetch the input operand values for a branch instruction.
    fn branch_rr(&mut self, instruction: &Instruction<F>) -> (Block<F>, Block<F>, F) {
        let a = self.mr(self.fp + instruction.op_a, MemoryAccessPosition::A);
        let b = self.get_b(instruction);

        let c = instruction.op_c[0];
        (a, b, c)
    }

    pub fn run(&mut self) {
        let early_exit_ts = std::env::var("RECURSION_EARLY_EXIT_TS")
            .map_or(usize::MAX, |ts: String| ts.parse().unwrap());
        while self.pc < F::from_canonical_u32(self.program.instructions.len() as u32) {
            let idx = self.pc.as_canonical_u32() as usize;
            let instruction = self.program.instructions[idx].clone();

            let mut next_pc = self.pc + F::one();
            let (a, b, c): (Block<F>, Block<F>, Block<F>);
            match instruction.opcode {
                Opcode::PrintF => {
                    self.nb_print_f += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = self.mr(a_ptr, MemoryAccessPosition::A);
                    println!("PRINTF={}, clk={}", a_val[0], self.timestamp);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::PrintE => {
                    self.nb_print_e += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = self.mr(a_ptr, MemoryAccessPosition::A);
                    println!("PRINTEF={:?}", a_val);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::CycleTracker => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = self.mr(a_ptr, MemoryAccessPosition::A);

                    let name = instruction.debug.clone();
                    let entry = self.cycle_tracker.entry(name).or_default();
                    if !entry.span_entered {
                        entry.span_entered = true;
                        entry.span_enter_cycle = self.timestamp;
                    } else {
                        entry.span_entered = false;
                        entry.cumulative_cycles += self.timestamp - entry.span_enter_cycle;
                    }

                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::ADD => {
                    self.nb_base_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val[0] = b_val[0] + c_val[0];
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::LessThanF => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val[0] = F::from_bool(b_val[0] < c_val[0]);
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::SUB => {
                    self.nb_base_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val[0] = b_val[0] - c_val[0];
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::MUL => {
                    self.nb_base_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val[0] = b_val[0] * c_val[0];
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::DIV => {
                    self.nb_base_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val[0] = b_val[0] / c_val[0];
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::EADD => {
                    self.nb_ext_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let sum = EF::from_base_slice(&b_val.0) + EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(sum.as_base_slice());
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::EMUL => {
                    self.nb_ext_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let product = EF::from_base_slice(&b_val.0) * EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(product.as_base_slice());
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::ESUB => {
                    self.nb_ext_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let diff = EF::from_base_slice(&b_val.0) - EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(diff.as_base_slice());
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::EDIV => {
                    self.nb_ext_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let quotient = EF::from_base_slice(&b_val.0) / EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(quotient.as_base_slice());
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::LOAD => {
                    self.nb_memory_ops += 1;
                    let (a_ptr, b_val, c_val) = self.mem_rr(&instruction);
                    let addr = Self::calculate_address(b_val, c_val, &instruction);

                    let val = self.mr(addr, MemoryAccessPosition::B);
                    let a_val = val;
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::STORE => {
                    self.nb_memory_ops += 1;
                    let (a_ptr, b_val, c_val) = self.mem_rr(&instruction);
                    let addr = Self::calculate_address(b_val, c_val, &instruction);

                    let a_val = self.mr(a_ptr, MemoryAccessPosition::A);
                    self.mw(addr, a_val, MemoryAccessPosition::B);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::BEQ => {
                    self.nb_branch_ops += 1;
                    let (a_val, b_val, c_offset) = self.branch_rr(&instruction);
                    (a, b, c) = (a_val, b_val, Block::from(c_offset));
                    if a[0] == b[0] {
                        next_pc = self.pc + c_offset;
                    }
                }
                Opcode::BNE => {
                    self.nb_branch_ops += 1;
                    let (a_val, b_val, c_offset) = self.branch_rr(&instruction);
                    (a, b, c) = (a_val, b_val, Block::from(c_offset));
                    if a[0] != b[0] {
                        next_pc = self.pc + c_offset;
                    }
                }
                Opcode::BNEINC => {
                    self.nb_branch_ops += 1;
                    let (mut a_val, b_val, c_offset) = self.branch_rr(&instruction);
                    a_val[0] += F::one();
                    if a_val[0] != b_val[0] {
                        next_pc = self.pc + c_offset;
                    }
                    self.mw(self.fp + instruction.op_a, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, Block::from(c_offset));
                }
                Opcode::EBEQ => {
                    self.nb_branch_ops += 1;
                    let (a_val, b_val, c_offset) = self.branch_rr(&instruction);
                    (a, b, c) = (a_val, b_val, Block::from(c_offset));
                    if a == b {
                        next_pc = self.pc + c_offset;
                    }
                }
                Opcode::EBNE => {
                    self.nb_branch_ops += 1;
                    let (a_val, b_val, c_offset) = self.branch_rr(&instruction);
                    (a, b, c) = (a_val, b_val, Block::from(c_offset));
                    if a != b {
                        next_pc = self.pc + c_offset;
                    }
                }
                Opcode::JAL => {
                    self.nb_branch_ops += 1;
                    let imm = instruction.op_b[0];
                    let a_ptr = instruction.op_a + self.fp;
                    self.mw(a_ptr, Block::from(self.pc), MemoryAccessPosition::A);
                    next_pc = self.pc + imm;
                    self.fp += instruction.op_c[0];
                    (a, b, c) = (Block::from(a_ptr), Block::default(), Block::default());
                }
                Opcode::JALR => {
                    self.nb_branch_ops += 1;
                    let imm = instruction.op_c;
                    let b_ptr = instruction.op_b[0] + self.fp;
                    let a_ptr = instruction.op_a + self.fp;
                    let b_val = self.mr(b_ptr, MemoryAccessPosition::B);
                    let c_val = imm;
                    let a_val = Block::from(self.pc + F::one());
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    next_pc = b_val[0];
                    self.fp = c_val[0];
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::TRAP => {
                    let trap_pc = self.pc.as_canonical_u32() as usize;
                    let trace = self.program.traces[trap_pc].clone();
                    if let Some(mut trace) = trace {
                        trace.resolve();
                        eprintln!("TRAP encountered. Backtrace:\n{:?}", trace);
                    } else {
                        for nearby_pc in (0..trap_pc).rev() {
                            let trace = self.program.traces[nearby_pc].clone();
                            if let Some(mut trace) = trace {
                                trace.resolve();
                                eprintln!(
                                    "TRAP encountered at pc={}. Nearest trace at pc={}: {:?}",
                                    trap_pc, nearby_pc, trace
                                );
                            }
                        }
                        eprintln!("TRAP encountered. No backtrace available");
                    }
                    exit(1);
                }
                Opcode::Ext2Felt => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = self.mr(a_ptr, MemoryAccessPosition::A);
                    let dst = a_val[0].as_canonical_u32() as usize;
                    self.memory.entry(dst).or_default().value[0] = b_val[0];
                    self.memory.entry(dst + 1).or_default().value[0] = b_val[1];
                    self.memory.entry(dst + 2).or_default().value[0] = b_val[2];
                    self.memory.entry(dst + 3).or_default().value[0] = b_val[3];
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::Poseidon2Perm => {
                    self.nb_poseidons += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = self.mr(a_ptr, MemoryAccessPosition::A);

                    // Get the dst array ptr.
                    let dst = a_val[0].as_canonical_u32() as usize;
                    // Get the src array ptr.
                    let src = b_val[0].as_canonical_u32() as usize;

                    let array: [_; PERMUTATION_WIDTH] = (src..(src + PERMUTATION_WIDTH))
                        .map(|addr| self.memory.entry(addr).or_default().value[0])
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap();

                    // Perform the permutation.
                    let result = self.perm.as_ref().unwrap().permute(array);

                    // Write the value back to the array at ptr.
                    // TODO: fix the timestamp as part of integrating the precompile if needed.
                    for (i, value) in result.iter().enumerate() {
                        self.memory.entry(dst + i).or_default().value[0] = *value;
                    }

                    self.record
                        .poseidon2_events
                        .push(Poseidon2Event { input: array });

                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::Poseidon2Compress => {
                    self.nb_poseidons += 1;

                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = self.mr(a_ptr, MemoryAccessPosition::A);

                    // Get the dst array ptr.
                    let dst = a_val[0].as_canonical_u32() as usize;
                    // Get the src array ptr.
                    let left = b_val[0].as_canonical_u32() as usize;
                    let right = c_val[0].as_canonical_u32() as usize;

                    let left_array: [_; PERMUTATION_WIDTH / 2] = (left..left
                        + PERMUTATION_WIDTH / 2)
                        .map(|addr| self.memory.entry(addr).or_default().value[0])
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap();
                    let right_array: [_; PERMUTATION_WIDTH / 2] = (right
                        ..right + PERMUTATION_WIDTH / 2)
                        .map(|addr| self.memory.entry(addr).or_default().value[0])
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap();
                    let array: [_; PERMUTATION_WIDTH] =
                        [left_array, right_array].concat().try_into().unwrap();

                    // Perform the permutation.
                    let result = self.perm.as_ref().unwrap().permute(array);

                    // Write the value back to the array at ptr.
                    // TODO: fix the timestamp as part of integrating the precompile if needed.
                    for (i, value) in result.iter().enumerate() {
                        self.memory.entry(dst + i).or_default().value[0] = *value;
                    }

                    self.record
                        .poseidon2_events
                        .push(Poseidon2Event { input: array });
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::HintBits => {
                    self.nb_bit_decompositions += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = self.mr(a_ptr, MemoryAccessPosition::A);

                    // Get the dst array ptr.
                    let dst = a_val[0].as_canonical_u32() as usize;
                    // Get the src value.
                    let num = b_val[0].as_canonical_u32();

                    // Decompose the num into bits.
                    let bits = (0..NUM_BITS).map(|i| (num >> i) & 1).collect::<Vec<_>>();
                    // Write the bits to the array at dst.
                    for (i, bit) in bits.iter().enumerate() {
                        self.memory.entry(dst + i).or_default().value[0] =
                            F::from_canonical_u32(*bit);
                    }
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::HintLen => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    self.mr(a_ptr, MemoryAccessPosition::A);
                    let a_val: Block<F> =
                        F::from_canonical_usize(self.witness_stream[0].len()).into();
                    self.mw(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::Hint => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = self.mr(a_ptr, MemoryAccessPosition::A);
                    let dst = a_val[0].as_canonical_u32() as usize;
                    let blocks = self.witness_stream.pop_front().unwrap();
                    for (i, block) in blocks.into_iter().enumerate() {
                        self.memory.entry(dst + i).or_default().value = block;
                    }
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::FRIFold => {
                    let a_val = self.mr(self.fp + instruction.op_a, MemoryAccessPosition::A);
                    let b_val = self.mr(self.fp + instruction.op_b[0], MemoryAccessPosition::B);
                    let c_val = Block::<F>::default();

                    // The timestamp for the memory reads for all of these operations will be self.clk.
                    let timestamp = self.clk;

                    let m = a_val[0];
                    let input_ptr = b_val[0];

                    // Read the input values.
                    let mut ptr = input_ptr;
                    let (z_record, z) = self.mr_record(ptr, timestamp);
                    let z: EF = z.ext();
                    ptr += F::one();
                    let (alpha_record, alpha) = self.mr_record(ptr, timestamp);
                    let alpha: EF = alpha.ext();
                    ptr += F::one();
                    let (x_record, x) = self.mr_record(ptr, timestamp);
                    let x = x[0];
                    ptr += F::one();
                    let (log_height_record, log_height) = self.mr_record(ptr, timestamp);
                    let log_height = log_height[0];
                    ptr += F::one();
                    let (mat_opening_ptr_record, mat_opening_ptr) = self.mr_record(ptr, timestamp);
                    let mat_opening_ptr = mat_opening_ptr[0];
                    ptr += F::two();
                    let (ps_at_z_ptr_record, ps_at_z_ptr) = self.mr_record(ptr, timestamp);
                    let ps_at_z_ptr = ps_at_z_ptr[0];
                    ptr += F::two();
                    let (alpha_pow_ptr_record, alpha_pow_ptr) = self.mr_record(ptr, timestamp);
                    let alpha_pow_ptr = alpha_pow_ptr[0];
                    ptr += F::two();
                    let (ro_ptr_record, ro_ptr) = self.mr_record(ptr, timestamp);
                    let ro_ptr = ro_ptr[0];

                    // Get the opening values.
                    let (p_at_x_record, p_at_x) = self.mr_record(mat_opening_ptr + m, timestamp);
                    let p_at_x: EF = p_at_x.ext();

                    let (p_at_z_record, p_at_z) = self.mr_record(ps_at_z_ptr + m, timestamp);
                    let p_at_z: EF = p_at_z.ext();

                    // Calculate the quotient and update the values
                    let quotient = (-p_at_z + p_at_x) / (-z + x);

                    // TODO: these will have to be changed to be "peek", because we write to them later
                    // Modify the ro and alpha pow values.
                    let (_, alpha_pow_at_log_height) =
                        self.mr_record(alpha_pow_ptr + log_height, timestamp);
                    let alpha_pow_at_log_height: EF = alpha_pow_at_log_height.ext();

                    // TODO: change this to "peek", because we will write it later.
                    let (_, ro_at_log_height) = self.mr_record(ro_ptr + log_height, timestamp);
                    let ro_at_log_height: EF = ro_at_log_height.ext();

                    let new_ro_at_log_height =
                        ro_at_log_height + alpha_pow_at_log_height * quotient;
                    let new_alpha_pow_at_log_height = alpha_pow_at_log_height * alpha;

                    let ro_at_log_height_record = self.mw_record(
                        ro_ptr + log_height,
                        Block::from(new_ro_at_log_height.as_base_slice()),
                        timestamp,
                    );

                    let alpha_pow_at_log_height_record = self.mw_record(
                        alpha_pow_ptr + log_height,
                        Block::from(new_alpha_pow_at_log_height.as_base_slice()),
                        timestamp,
                    );

                    self.record.fri_fold_events.push(FriFoldEvent {
                        clk: self.clk,
                        m,
                        input_ptr,
                        z: z_record,
                        alpha: alpha_record,
                        x: x_record,
                        log_height: log_height_record,
                        mat_opening_ptr: mat_opening_ptr_record,
                        ps_at_z_ptr: ps_at_z_ptr_record,
                        alpha_pow_ptr: alpha_pow_ptr_record,
                        ro_ptr: ro_ptr_record,
                        p_at_x: p_at_x_record,
                        p_at_z: p_at_z_record,
                        alpha_pow_at_log_height: alpha_pow_at_log_height_record,
                        ro_at_log_height: ro_at_log_height_record,
                    });

                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::Commit => {
                    let a_val = self.mr(self.fp + instruction.op_a, MemoryAccessPosition::A);
                    let b_val = Block::<F>::default();
                    let c_val = Block::<F>::default();

                    let hash_ptr = a_val[0].as_canonical_u32() as usize;

                    for i in 0..DIGEST_SIZE {
                        self.record.public_values_digest[i] =
                            self.memory.entry(hash_ptr + i).or_default().value[0];
                    }

                    (a, b, c) = (a_val, b_val, c_val);
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
            self.timestamp += 1;
            self.access = CpuRecord::default();

            if self.timestamp >= early_exit_ts {
                break;
            }
        }

        // Collect all used memory addresses.
        for addr in 0..self.memory.len() {
            let entry = self.memory.entry(addr).or_default();
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

#[cfg(test)]
mod tests {
    use p3_field::AbstractField;
    use sp1_core::{
        stark::{RiscvAir, StarkGenericConfig},
        utils::BabyBearPoseidon2,
    };

    use super::{Instruction, Opcode, RecursionProgram, Runtime};

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type A = RiscvAir<F>;

    #[test]
    fn test_witness() {
        let zero = F::zero();
        let zero_block = [F::zero(); 4];
        let program = RecursionProgram {
            traces: vec![],
            instructions: vec![
                Instruction::new(
                    Opcode::HintLen,
                    zero,
                    zero_block,
                    zero_block,
                    zero,
                    zero,
                    false,
                    false,
                    "".to_string(),
                ),
                Instruction::new(
                    Opcode::PrintF,
                    zero,
                    zero_block,
                    zero_block,
                    zero,
                    zero,
                    false,
                    false,
                    "".to_string(),
                ),
            ],
        };
        let machine = A::machine(SC::default());
        let mut runtime = Runtime::<F, EF, _>::new(&program, machine.config().perm.clone());
        runtime.witness_stream =
            vec![vec![F::two().into(), F::two().into(), F::two().into()]].into();
        runtime.run();
    }
}
