mod instruction;
mod opcode;
mod program;
mod record;

use nohash_hasher::BuildNoHashHasher;
use std::collections::VecDeque;
use std::hash::Hash;
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
    pub memory: Option<MemoryRecord<F>>,
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

    /// Uninitialized memory addresses that have a specific value they should be initialized with.
    /// The Opcodes that start with Hint* utilize this to set memory values.
    pub uninitialized_memory: HashMap<F, Block<F>, BuildNoHashHasher<F>>,

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
            uninitialized_memory: HashMap::new(),
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
            uninitialized_memory: HashMap::new(),
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

    // Peek at the memory without touching the record.
    fn peek(&mut self, addr: F) -> Block<F> {
        self.memory
            .get(&(addr.as_canonical_u32() as usize))
            .map(|entry| entry.value)
            .unwrap_or_else(Block::default)
    }

    fn mr(&mut self, addr: F, timestamp: F) -> (MemoryRecord<F>, Block<F>) {
        let entry = self
            .memory
            .entry(addr.as_canonical_u32() as usize)
            .or_default();
        let (prev_value, prev_timestamp) = (entry.value, entry.timestamp);
        let record = MemoryRecord {
            addr,
            value: prev_value,
            timestamp,
            prev_value,
            prev_timestamp,
        };
        *entry = MemoryEntry {
            value: prev_value,
            timestamp,
        };
        (record, prev_value)
    }

    fn mr_cpu(&mut self, addr: F, position: MemoryAccessPosition) -> Block<F> {
        let timestamp = self.timestamp(&position);
        let record = self.mr(addr, timestamp);
        match position {
            MemoryAccessPosition::A => self.access.a = Some(record),
            MemoryAccessPosition::B => self.access.b = Some(record),
            MemoryAccessPosition::C => self.access.c = Some(record),
            MemoryAccessPosition::Memory => self.access.memory = Some(record),
        };
        prev_value
    }

    fn mw_uninitialized(&mut self, addr: F, value: Block<F>) {
        self.uninitialized_memory
            .entry(addr)
            .and_modify(|_| panic!("address already initialized"))
            .or_insert(value);
    }

    fn mw(&mut self, addr: F, value: Block<F>, timestamp: F) -> MemoryRecord<F> {
        let addr_usize = addr.as_canonical_u32() as usize;
        let entry = self.memory.entry(addr_usize).or_default();
        let (prev_value, prev_timestamp) = (entry.value, entry.timestamp);
        let record = MemoryRecord {
            addr,
            value,
            timestamp,
            prev_value,
            prev_timestamp,
        };
        *entry = MemoryEntry { value, timestamp };
        record
    }

    fn mw_cpu(&mut self, addr: F, value: Block<F>, position: MemoryAccessPosition) {
        let timestamp = self.timestamp(&position);
        let record = self.mw(addr, value, timestamp);
        match position {
            MemoryAccessPosition::A => self.access.a = Some(record),
            MemoryAccessPosition::B => self.access.b = Some(record),
            MemoryAccessPosition::C => self.access.c = Some(record),
            MemoryAccessPosition::Memory => self.access.memory = Some(record),
            _ => unreachable!(),
        };
    }

    fn get_memory_entry(&mut self, addr: F) -> &mut MemoryEntry<F> {
        self.memory
            .entry(addr.as_canonical_u32() as usize)
            .or_default()
    }

    fn timestamp(&self, position: &MemoryAccessPosition) -> F {
        self.clk + F::from_canonical_u32(*position as u32)
    }

    // When we read the "a" position, it is never an immediate value, so we always read from memory.
    fn get_a(&mut self, instruction: &Instruction<F>) -> Block<F> {
        self.mr_cpu(self.fp + instruction.op_a[0], MemoryAccessPosition::A)
    }

    // Useful to peek at the value of the "a" position without updating the access record.
    // This assumes that there will be a write later.
    fn peek_a(&self, instruction: &Instruction<F>) -> (F, Block<F>) {
        let addr = self.fp + instruction.op_a[0];
        (
            addr,
            self.memory
                .get(&(addr.as_canonical_u32() as usize))
                .map(|entry| entry.value)
                .unwrap_or_else(Block::default),
        )
    }

    fn get_b(&mut self, instruction: &Instruction<F>) -> Block<F> {
        if instruction.imm_b_base() {
            Block::from(instruction.op_b[0])
        } else if instruction.imm_b {
            instruction.op_b
        } else {
            self.mr_cpu(self.fp + instruction.op_b[0], MemoryAccessPosition::B)
        }
    }

    fn get_c(&mut self, instruction: &Instruction<F>) -> Block<F> {
        if instruction.imm_c_base() {
            Block::from(instruction.op_c[0])
        } else if instruction.imm_c {
            instruction.op_c
        } else {
            self.mr_cpu(self.fp + instruction.op_c[0], MemoryAccessPosition::C)
        }
    }

    /// Just read all the values for an instruction.
    fn all_rr(&mut self, instruction: &Instruction<F>) -> (Block<F>, Block<F>, Block<F>) {
        let a_val = self.get_a(instruction);
        let b_val = self.get_b(instruction);
        let c_val = self.get_c(instruction);

        (a_val, b_val, c_val)
    }

    /// Fetch the destination address and input operand values for an ALU instruction.
    fn alu_rr(&mut self, instruction: &Instruction<F>) -> (F, Block<F>, Block<F>) {
        let a_ptr = self.fp + instruction.op_a;
        let c_val = self.get_c(instruction);
        let b_val = self.get_b(instruction);

        (a_ptr, b_val, c_val)
    }

    /// Fetch the destination address input operand values for a load instruction (from heap).
    fn load_rr(&mut self, instruction: &Instruction<F>) -> (F, Block<F>, Block<F>, Block<F>) {
        let offset = instruction.offset_imm;
        let size = instruction.size_imm;

        let a_ptr = self.fp + instruction.op_a;
        let b_val = self.get_b(instruction);
        let c_val = self.get_c(instruction);

        let index = c_val[0];
        let addr = b_val[0] + index * size + offset;
        let memory_val = self.mr_cpu(addr, MemoryAccessPosition::Memory);

        (a_ptr, b_val, c_val, memory_val)
    }

    /// Fetch the destination address input operand values for a store instruction (from stack).
    fn store_rr(&mut self, instruction: &Instruction<F>) -> (Block<F>, Block<F>, Block<F>) {
        let offset = instruction.offset_imm;
        let size = instruction.size_imm;

        let c_val = self.get_c(instruction);
        let b_val = self.get_b(instruction);
        let a_val = self.get_a(instruction);

        let index = c_val[0];
        let addr = b_val[0] + index * size + offset;

        self.mw_cpu(addr, a_val, MemoryAccessPosition::Memory);

        (a_val, b_val, c_val)
    }

    /// Fetch the input operand values for a branch instruction.
    fn branch_rr(&mut self, instruction: &Instruction<F>) -> (Block<F>, Block<F>, F) {
        let a = self.get_a(instruction);
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
                Opcode::PrintF => {
                    self.nb_print_f += 1;
                    let (a_val, b_val, c_val) = self.all_rr(&instruction);
                    println!("PRINTF={}, clk={}", a_val[0], self.timestamp);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::PrintE => {
                    self.nb_print_e += 1;
                    let (a_val, b_val, c_val) = self.all_rr(&instruction);
                    println!("PRINTEF={:?}", a_val);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::CycleTracker => {
                    let (a_val, b_val, c_val) = self.all_rr(&instruction);

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
                    a_val.0[0] = b_val.0[0] + c_val.0[0];
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::LessThanF => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val.0[0] = F::from_bool(b_val.0[0] < c_val.0[0]);
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::SUB => {
                    self.nb_base_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val.0[0] = b_val.0[0] - c_val.0[0];
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::MUL => {
                    self.nb_base_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val.0[0] = b_val.0[0] * c_val.0[0];
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::DIV => {
                    self.nb_base_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val.0[0] = b_val.0[0] / c_val.0[0];
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::EADD | Opcode::EFADD => {
                    self.nb_ext_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let sum = EF::from_base_slice(&b_val.0) + EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(sum.as_base_slice());
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::EMUL | Opcode::EFMUL => {
                    self.nb_ext_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let product = EF::from_base_slice(&b_val.0) * EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(product.as_base_slice());
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::ESUB | Opcode::EFSUB | Opcode::FESUB => {
                    self.nb_ext_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let diff = EF::from_base_slice(&b_val.0) - EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(diff.as_base_slice());
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::EDIV | Opcode::EFDIV | Opcode::FEDIV => {
                    self.nb_ext_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let quotient = EF::from_base_slice(&b_val.0) / EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(quotient.as_base_slice());
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::LW => {
                    self.nb_memory_ops += 1;
                    let (a_ptr, b_val, c_val, memory_val) = self.load_rr(&instruction);
                    self.mw_cpu(a_ptr, memory_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                // For store, branch opcodes, we read from the a operand, instead of writing.
                Opcode::SW => {
                    self.nb_memory_ops += 1;
                    let (a_val, b_val, c_val) = self.store_rr(&instruction);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::BEQ => {
                    self.nb_branch_ops += 1;
                    let (a_val, b_val, c_offset) = self.branch_rr(&instruction);
                    (a, b, c) = (a_val, b_val, Block::from(c_offset));
                    if a == b {
                        next_pc = self.pc + c_offset;
                    }
                }
                Opcode::BNE => {
                    self.nb_branch_ops += 1;
                    let (a_val, b_val, c_offset) = self.branch_rr(&instruction);
                    (a, b, c) = (a_val, b_val, Block::from(c_offset));
                    if a != b {
                        next_pc = self.pc + c_offset;
                    }
                }
                // For this opcode, we write to the a register, but constraint it to be incremented by 1.
                Opcode::BNEINC => {
                    self.nb_branch_ops += 1;
                    let c_offset = instruction.op_c[0];
                    let b_val = self.get_b(&instruction);
                    let (a_ptr, mut a_val) = self.peek_a(&instruction);
                    a_val += EF::one();
                    if a_val != b_val {
                        next_pc = self.pc + c_offset;
                    }
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, Block::from(c_offset));
                }
                Opcode::JAL => {
                    self.nb_branch_ops += 1;
                    // These are both immediates.
                    let c_val = self.get_c(&instruction);
                    let b_val = self.get_b(&instruction);
                    let a_ptr = instruction.op_a + self.fp;
                    self.mw_cpu(a_ptr, Block::from(self.pc), MemoryAccessPosition::A);
                    next_pc = self.pc + b_val[0];
                    self.fp += c_val[0];
                    (a, b, c) = (Block::from(a_ptr), Block::default(), Block::default());
                }
                Opcode::JALR => {
                    self.nb_branch_ops += 1;
                    let c_val = self.get_c(&instruction);
                    let b_val = self.get_b(&instruction);
                    let a_ptr = instruction.op_a + self.fp;
                    let a_val: Block<F> = Block::from(self.pc + F::one());
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    next_pc = b_val.0[0];
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
                Opcode::Poseidon2Compress => {
                    self.nb_poseidons += 1;

                    let (a_val, b_val, c_val) = self.all_rr(&instruction);
                    // Get the dst array ptr.
                    let dst = a_val[0].as_canonical_u32() as usize;
                    // Get the src array ptr.
                    let left = b_val[0].as_canonical_u32() as usize;
                    let right = c_val[0].as_canonical_u32() as usize;

                    let timestamp = self.clk;

                    let left_array: [_; PERMUTATION_WIDTH / 2] = (left..left
                        + PERMUTATION_WIDTH / 2)
                        .map(|addr| self.mr(addr, timestamp))
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap();
                    let right_array: [_; PERMUTATION_WIDTH / 2] = (right
                        ..right + PERMUTATION_WIDTH / 2)
                        .map(|addr| self.mr(addr, timestamp))
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap();
                    let array: [F; PERMUTATION_WIDTH] = [left_array, right_array]
                        .concat()
                        .map(|x| x.1 .0[0]) // Grab the 2nd entry (the Block) and grab the first element.
                        .try_into()
                        .unwrap();

                    // Perform the permutation.
                    let result = self.perm.as_ref().unwrap().permute(array);

                    // Write the value back to the array at ptr.
                    for (i, value) in result.iter().enumerate() {
                        self.mw(dst + i, Block::from(*value), timestamp + 1);
                    }

                    // TODO: include all of the records in the Poseidon2Event.
                    self.record
                        .poseidon2_events
                        .push(Poseidon2Event { input: array });
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::HintExt2Felt => {
                    let (a_val, b_val, c_val) = self.all_rr(&instruction);
                    let dst: usize = a_val[0].as_canonical_u32() as usize;
                    self.mw_uninitialized(dst, Block::from(b_val[0]));
                    self.mw_uninitialized(dst + 1, Block::from(b_val[1]));
                    self.mw_uninitialized(dst + 2, Block::from(b_val[2]));
                    self.mw_uninitialized(dst + 3, Block::from(b_val[3]));
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::HintBits => {
                    self.nb_bit_decompositions += 1;
                    let (a_val, b_val, c_val) = self.all_rr(&instruction);

                    // Get the dst array ptr.
                    let dst = a_val[0].as_canonical_u32() as usize;
                    // Get the src value.
                    let num = b_val[0].as_canonical_u32();

                    // Decompose the num into bits.
                    let bits = (0..NUM_BITS).map(|i| (num >> i) & 1).collect::<Vec<_>>();
                    // Write the bits to the array at dst.
                    for (i, bit) in bits.iter().enumerate() {
                        self.mw_uninitialized(dst + i, Block::from(F::from_canonical_u32(*bit)));
                    }
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::HintLen => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val: Block<F> =
                        F::from_canonical_usize(self.witness_stream[0].len()).into();
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::Hint => {
                    let (a_val, b_val, c_val) = self.all_rr(&instruction);
                    let dst = a_val[0].as_canonical_u32() as usize;
                    let blocks = self.witness_stream.pop_front().unwrap();
                    for (i, block) in blocks.into_iter().enumerate() {
                        self.mw_uninitialized(dst + i, block);
                    }
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::FRIFold => {
                    let (a_val, b_val, c_val) = self.all_rr(&instruction);

                    let m = a_val[0].as_canonical_u32() as usize;
                    let input_ptr = b_val[0].as_canonical_u32() as usize;

                    let timestamp = self.clk;

                    // Read the input values.
                    let mut ptr = input_ptr;
                    let (z_record, z) = self.mr(ptr, timestamp);
                    let (alpha_record, alpha) = self.mr(ptr + 1, timestamp);
                    let (x_record, x) = self.mr(ptr + 2, timestamp);
                    let (log_height_record, log_height_ef) = self.mr(ptr + 3, timestamp);
                    let (mat_opening_record, mat_opening) = self.mr(ptr + 4, timestamp);
                    let (ps_at_z_record, ps_at_z) = self.mr(ptr + 7, timestamp);
                    let (alpha_pow_record, alpha_pow) = self.mr(ptr + 9, timestamp);
                    let (ro_record, ro) = self.mr(ptr + 11, timestamp);

                    let log_height = log_height_ef[0];
                    let mat_opening_ptr: F = mat_opening[0];
                    let ps_at_z_ptr = ps_at_z[0];
                    let alpha_pow_ptr = alpha_pow[0];
                    let ro_ptr = ro[0];

                    // Get the opening values.
                    let (p_at_x_record, p_at_x) = self.mr(mat_opening_ptr + m, timestamp);
                    let (p_at_z_record, p_at_z) = self.mr(ps_at_z_ptr + m, timestamp);

                    // Calculate the quotient and update the values
                    let quotient = (-p_at_z + p_at_x) / (-z + x);

                    // Modify the ro and alpha pow values.
                    let alpha_pow_at_log_height = self.peek(alpha_pow_ptr + log_height);
                    let ro_at_log_height = self.peek(ro_ptr + log_height);

                    let row_ptr_at_log_height_record = self.mw(
                        ro_ptr + log_height,
                        ro_at_log_height + alpha_pow_at_log_height * quotient,
                        timestamp + 1,
                    );

                    let alpha_pow_at_log_height_record = self.mw(
                        alpha_pow_ptr + log_height,
                        alpha_pow_at_log_height * alpha,
                        timestamp + 1,
                    );

                    // TODO: emit FRI Fold event with all of these records.

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
