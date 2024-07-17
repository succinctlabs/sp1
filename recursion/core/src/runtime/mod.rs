mod instruction;
mod opcode;
mod program;
mod record;
mod utils;

use std::collections::VecDeque;
use std::{array, fmt};
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
pub use utils::*;

use crate::air::{Block, RECURSION_PUBLIC_VALUES_COL_MAP, RECURSIVE_PROOF_NUM_PV_ELTS};
use crate::cpu::CpuEvent;
use crate::exp_reverse_bits::ExpReverseBitsLenEvent;
use crate::fri_fold::FriFoldEvent;
use crate::memory::{compute_addr_diff, MemoryRecord};
use crate::poseidon2_wide::events::{
    Poseidon2AbsorbEvent, Poseidon2CompressEvent, Poseidon2FinalizeEvent, Poseidon2HashEvent,
};
use crate::range_check::{RangeCheckEvent, RangeCheckOpcode};

use p3_field::{ExtensionField, PrimeField32};
use sp1_core::runtime::MemoryAccessPosition;

/// The heap pointer address.
pub const HEAP_PTR: i32 = -4;
pub const HEAP_START_ADDRESS: usize = STACK_SIZE + 4;

pub const STACK_SIZE: usize = 1 << 24;
pub const MEMORY_SIZE: usize = 1 << 28;

/// The width of the Poseidon2 permutation.
pub const PERMUTATION_WIDTH: usize = 16;
pub const POSEIDON2_SBOX_DEGREE: u64 = 7;
pub const HASH_RATE: usize = 8;

/// The current verifier implementation assumes that we are using a 256-bit hash with 32-bit elements.
pub const DIGEST_SIZE: usize = 8;

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
    pub uninitialized_memory: HashMap<usize, Block<F>>,

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

    p2_hash_state: [F; PERMUTATION_WIDTH],

    p2_hash_state_cursor: usize,

    p2_current_hash_num: Option<F>,

    _marker: PhantomData<EF>,
}

#[derive(Debug)]
pub enum RuntimeError {
    Trap(String),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeError::Trap(msg) => write!(f, "TRAP encountered: {}", msg),
        }
    }
}

impl std::error::Error for RuntimeError {}

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
            p2_hash_state: [F::zero(); PERMUTATION_WIDTH],
            p2_hash_state_cursor: 0,
            p2_current_hash_num: None,
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
            p2_hash_state: [F::zero(); PERMUTATION_WIDTH],
            p2_hash_state_cursor: 0,
            p2_current_hash_num: None,
            _marker: PhantomData,
        }
    }

    pub fn print_stats(&self) {
        tracing::debug!("Total Cycles: {}", self.timestamp);
        tracing::debug!("Poseidon Operations: {}", self.nb_poseidons);
        tracing::debug!("Field Operations: {}", self.nb_base_ops);
        tracing::debug!("Extension Operations: {}", self.nb_ext_ops);
        tracing::debug!("Memory Operations: {}", self.nb_memory_ops);
        tracing::debug!("Branch Operations: {}", self.nb_branch_ops);
        for (name, entry) in self.cycle_tracker.iter().sorted_by_key(|(name, _)| *name) {
            tracing::debug!("> {}: {}", name, entry.cumulative_cycles);
        }
    }

    // Peek at the memory without touching the record.
    fn peek(&mut self, addr: F) -> (F, Block<F>) {
        (
            addr,
            self.memory
                .get(&(addr.as_canonical_u32() as usize))
                .unwrap()
                .value,
        )
    }

    // Write to uninitialized memory.
    fn mw_uninitialized(&mut self, addr: usize, value: Block<F>) {
        // Write it to uninitialized memory for creating MemoryInit table later.
        self.uninitialized_memory
            .entry(addr)
            .and_modify(|_| panic!("address already initialized"))
            .or_insert(value);
        // Also write it to the memory map so that it can be read later.
        self.memory
            .entry(addr)
            .and_modify(|_| panic!("address already initialized"))
            .or_insert(MemoryEntry {
                value,
                timestamp: F::zero(),
            });
    }

    /// Given a MemoryRecord event, track the range checks for the memory access.
    /// This will be used later to set the multiplicities in the range check table.
    fn track_memory_range_checks(&mut self, record: &MemoryRecord<F>) {
        let diff_16bit_limb_event = RangeCheckEvent::new(
            RangeCheckOpcode::U16,
            record.diff_16bit_limb.as_canonical_u32() as u16,
        );
        let diff_12bit_limb_event = RangeCheckEvent::new(
            RangeCheckOpcode::U12,
            record.diff_12bit_limb.as_canonical_u32() as u16,
        );
        self.record
            .add_range_check_events(&[diff_16bit_limb_event, diff_12bit_limb_event]);
    }

    /// Track the range checks for the memory finalize table. This will be used later to set the
    /// multiplicities in the range check table. The parameter `subtract_one` should be `true` when
    /// used for checking address uniqueness, and `false` when used to range-check the addresses
    /// themselves.
    fn track_addr_range_check(&mut self, addr: F, next_addr: F, subtract_one: bool) {
        let (diff_16, diff_12) = compute_addr_diff(next_addr, addr, subtract_one);
        let diff_16bit_limb_event =
            RangeCheckEvent::new(RangeCheckOpcode::U16, diff_16.as_canonical_u32() as u16);
        let diff_8bit_limb_event =
            RangeCheckEvent::new(RangeCheckOpcode::U12, diff_12.as_canonical_u32() as u16);
        self.record
            .add_range_check_events(&[diff_16bit_limb_event, diff_8bit_limb_event]);
    }

    fn mr(&mut self, addr: F, timestamp: F) -> (MemoryRecord<F>, Block<F>) {
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
        self.track_memory_range_checks(&record);
        (record, prev_value)
    }

    fn mr_cpu(&mut self, addr: F, position: MemoryAccessPosition) -> Block<F> {
        let timestamp = self.timestamp(&position);
        let (record, value) = self.mr(addr, timestamp);
        match position {
            MemoryAccessPosition::A => self.access.a = Some(record),
            MemoryAccessPosition::B => self.access.b = Some(record),
            MemoryAccessPosition::C => self.access.c = Some(record),
            MemoryAccessPosition::Memory => self.access.memory = Some(record),
        };
        value
    }

    fn mw(&mut self, addr: F, value: impl Into<Block<F>>, timestamp: F) -> MemoryRecord<F> {
        let addr_usize = addr.as_canonical_u32() as usize;
        let entry = self.memory.entry(addr_usize).or_default();
        let (prev_value, prev_timestamp) = (entry.value, entry.timestamp);
        let value_as_block = value.into();
        let record =
            MemoryRecord::new_write(addr, value_as_block, timestamp, prev_value, prev_timestamp);
        *entry = MemoryEntry {
            value: value_as_block,
            timestamp,
        };
        self.track_memory_range_checks(&record);
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
        };
    }

    fn timestamp(&self, position: &MemoryAccessPosition) -> F {
        self.clk + F::from_canonical_u32(*position as u32)
    }

    // When we read the "a" position, it is never an immediate value, so we always read from memory.
    fn get_a(&mut self, instruction: &Instruction<F>) -> Block<F> {
        self.mr_cpu(self.fp + instruction.op_a, MemoryAccessPosition::A)
    }

    // Useful to peek at the value of the "a" position without updating the access record.
    // This assumes that there will be a write later, which is why it also returns the addr.
    fn peek_a(&self, instruction: &Instruction<F>) -> (F, Block<F>) {
        let addr = self.fp + instruction.op_a;
        (
            addr,
            self.memory
                .get(&(addr.as_canonical_u32() as usize))
                .map(|entry| entry.value)
                .unwrap_or_default(),
        )
    }

    fn get_b(&mut self, instruction: &Instruction<F>) -> Block<F> {
        if instruction.imm_b {
            instruction.op_b
        } else {
            self.mr_cpu(self.fp + instruction.op_b[0], MemoryAccessPosition::B)
        }
    }

    fn get_c(&mut self, instruction: &Instruction<F>) -> Block<F> {
        if instruction.imm_c {
            instruction.op_c
        } else {
            self.mr_cpu(self.fp + instruction.op_c[0], MemoryAccessPosition::C)
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
        let c = instruction.op_c[0];
        let b = self.get_b(instruction);
        let a = self.get_a(instruction);
        (a, b, c)
    }

    /// Read all the values for an instruction.
    fn all_rr(&mut self, instruction: &Instruction<F>) -> (Block<F>, Block<F>, Block<F>) {
        let c_val = self.get_c(instruction);
        let b_val = self.get_b(instruction);
        let a_val = self.get_a(instruction);
        (a_val, b_val, c_val)
    }

    pub fn run(&mut self) -> Result<(), RuntimeError> {
        let early_exit_ts = std::env::var("RECURSION_EARLY_EXIT_TS")
            .map_or(usize::MAX, |ts: String| ts.parse().unwrap());
        while self.pc < F::from_canonical_u32(self.program.instructions.len() as u32) {
            let idx = self.pc.as_canonical_u32() as usize;
            let instruction = self.program.instructions[idx].clone();

            let mut next_clk = self.clk + F::from_canonical_u32(4);
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
                    a_val[0] = b_val[0] + c_val[0];
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);

                    // If the instruction is a heap expansion, we need to add a range check event to
                    // ensure that the heap size never goes above 2^28.
                    if instruction_is_heap_expand(&instruction) {
                        let (u16_range_check, u12_range_check) =
                            get_heap_size_range_check_events(a_val[0]);
                        self.record
                            .add_range_check_events(&[u16_range_check, u12_range_check]);
                    }

                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::LessThanF => {
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val[0] = F::from_bool(b_val[0] < c_val[0]);
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::SUB => {
                    self.nb_base_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val[0] = b_val[0] - c_val[0];
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::MUL => {
                    self.nb_base_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val = Block::default();
                    a_val[0] = b_val[0] * c_val[0];
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::DIV => {
                    self.nb_base_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let mut a_val: Block<F> = Block::default();
                    a_val[0] = b_val[0] / c_val[0];
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::EADD => {
                    self.nb_ext_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let sum = EF::from_base_slice(&b_val.0) + EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(sum.as_base_slice());
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::EMUL => {
                    self.nb_ext_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let product = EF::from_base_slice(&b_val.0) * EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(product.as_base_slice());
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::ESUB => {
                    self.nb_ext_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let diff = EF::from_base_slice(&b_val.0) - EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(diff.as_base_slice());
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::EDIV => {
                    self.nb_ext_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let quotient = EF::from_base_slice(&b_val.0) / EF::from_base_slice(&c_val.0);
                    let a_val = Block::from(quotient.as_base_slice());
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::LOAD => {
                    self.nb_memory_ops += 1;
                    let (a_ptr, b_val, c_val) = self.mem_rr(&instruction);
                    let addr = Self::calculate_address(b_val, c_val, &instruction);
                    let a_val = self.mr_cpu(addr, MemoryAccessPosition::Memory);
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::STORE => {
                    self.nb_memory_ops += 1;
                    let (a_ptr, b_val, c_val) = self.mem_rr(&instruction);
                    let addr = Self::calculate_address(b_val, c_val, &instruction);
                    let a_val = self.mr_cpu(a_ptr, MemoryAccessPosition::A);
                    self.mw_cpu(addr, a_val, MemoryAccessPosition::Memory);
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
                Opcode::BNEINC => {
                    self.nb_branch_ops += 1;
                    let (_, b_val, c_offset) = self.alu_rr(&instruction);
                    let (a_ptr, mut a_val) = self.peek_a(&instruction);
                    a_val[0] += F::one();
                    if a_val != b_val {
                        next_pc = self.pc + c_offset[0];
                    }
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    (a, b, c) = (a_val, b_val, c_offset);
                }
                Opcode::JAL => {
                    self.nb_branch_ops += 1;
                    let (a_ptr, b_val, c_offset) = self.alu_rr(&instruction);
                    let a_val = Block::from(self.pc);
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    next_pc = self.pc + b_val[0];
                    self.fp += c_offset[0];
                    (a, b, c) = (a_val, b_val, c_offset);
                }
                Opcode::JALR => {
                    self.nb_branch_ops += 1;
                    let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
                    let a_val = Block::from(self.pc + F::one());
                    self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
                    next_pc = b_val[0];
                    self.fp = c_val[0];
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::TRAP => {
                    self.record
                        .public_values
                        .resize(RECURSIVE_PROOF_NUM_PV_ELTS, F::zero());
                    self.record.public_values[RECURSION_PUBLIC_VALUES_COL_MAP.exit_code] = F::one();

                    let trap_pc = self.pc.as_canonical_u32() as usize;
                    let trace = self.program.traces[trap_pc].clone();
                    if let Some(mut trace) = trace {
                        trace.resolve();
                        return Err(RuntimeError::Trap(format!("Backtrace:\n{:?}", trace)));
                    } else {
                        for nearby_pc in (0..trap_pc).rev() {
                            let trace = self.program.traces[nearby_pc].clone();
                            if let Some(mut trace) = trace {
                                trace.resolve();
                                return Err(RuntimeError::Trap(format!(
                                    "TRAP encountered at pc={}. Nearest trace at pc={}: {:?}",
                                    trap_pc, nearby_pc, trace
                                )));
                            }
                        }
                        return Err(RuntimeError::Trap("No backtrace available".to_string()));
                    }
                }
                Opcode::HALT => {
                    self.record
                        .public_values
                        .resize(RECURSIVE_PROOF_NUM_PV_ELTS, F::zero());
                    self.record.public_values[RECURSION_PUBLIC_VALUES_COL_MAP.exit_code] =
                        F::zero();

                    let (a_val, b_val, c_val) = self.all_rr(&instruction);
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::HintExt2Felt => {
                    let (a_val, b_val, c_val) = self.all_rr(&instruction);
                    let dst = a_val[0].as_canonical_u32() as usize;
                    self.mw_uninitialized(dst, Block::from(b_val[0]));
                    self.mw_uninitialized(dst + 1, Block::from(b_val[1]));
                    self.mw_uninitialized(dst + 2, Block::from(b_val[2]));
                    self.mw_uninitialized(dst + 3, Block::from(b_val[3]));
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::Poseidon2Compress => {
                    self.nb_poseidons += 1;

                    let (a_val, b_val, c_val) = self.all_rr(&instruction);

                    // Get the dst array ptr.
                    let dst = a_val[0];
                    // Get the src array ptr.
                    let left = b_val[0];
                    let right = c_val[0] + instruction.offset_imm;

                    let timestamp = self.clk;

                    let mut left_records = vec![];
                    let mut right_records = vec![];
                    let mut left_array: [F; PERMUTATION_WIDTH / 2] =
                        [F::zero(); PERMUTATION_WIDTH / 2];
                    let mut right_array: [F; PERMUTATION_WIDTH / 2] =
                        [F::zero(); PERMUTATION_WIDTH / 2];

                    for i in 0..PERMUTATION_WIDTH / 2 {
                        let f_i = F::from_canonical_u32(i as u32);
                        let left_val = self.mr(left + f_i, timestamp);
                        let right_val = self.mr(right + f_i, timestamp);
                        left_array[i] = left_val.1 .0[0];
                        right_array[i] = right_val.1 .0[0];
                        left_records.push(left_val.0);
                        right_records.push(right_val.0);
                    }
                    let array: [_; PERMUTATION_WIDTH] =
                        [left_array, right_array].concat().try_into().unwrap();
                    let input_records: [_; PERMUTATION_WIDTH] =
                        [left_records, right_records].concat().try_into().unwrap();

                    // Perform the permutation.
                    let result = self.perm.as_ref().unwrap().permute(array);

                    // Write the value back to the array at ptr.
                    let mut result_records = vec![];
                    for (i, value) in result.iter().enumerate() {
                        result_records.push(self.mw(
                            dst + F::from_canonical_usize(i),
                            Block::from(*value),
                            timestamp + F::one(),
                        ));
                    }

                    self.record
                        .poseidon2_compress_events
                        .push(Poseidon2CompressEvent {
                            clk: timestamp,
                            dst,
                            left,
                            right,
                            input: array,
                            result_array: result,
                            input_records,
                            result_records: result_records.try_into().unwrap(),
                        });

                    (a, b, c) = (a_val, b_val, c_val);
                }

                Opcode::Poseidon2Absorb => {
                    self.nb_poseidons += 1;
                    let (a_val, b_val, c_val) = self.all_rr(&instruction);

                    let hash_and_absorb_num = a_val[0];
                    let start_addr = b_val[0];
                    let input_len = c_val[0];
                    let timestamp = self.clk;

                    let two_pow_12 = 1 << 12;

                    let hash_and_absorb_num_u32 = hash_and_absorb_num.as_canonical_u32();
                    let hash_num = F::from_canonical_u32(hash_and_absorb_num_u32 / two_pow_12);
                    let absorb_num = F::from_canonical_u32(hash_and_absorb_num_u32 % two_pow_12);

                    // Double check that hash_num is [0, 2^16 - 1] and absorb_num is [0, 2^12 - 1] since
                    // that is what the AIR will enforce.
                    assert!(hash_num.as_canonical_u32() < 1 << 16);
                    assert!(absorb_num.as_canonical_u32() < 1 << 12);

                    // We currently don't support an input_len of 0, since it will need special logic in the AIR.
                    assert!(input_len > F::zero());

                    let mut absorb_event = Poseidon2AbsorbEvent::new(
                        timestamp,
                        hash_and_absorb_num,
                        start_addr,
                        input_len,
                        hash_num,
                        absorb_num,
                    );

                    let memory_records: Vec<MemoryRecord<F>> = (0..input_len.as_canonical_u32())
                        .map(|i| self.mr(start_addr + F::from_canonical_u32(i), timestamp).0)
                        .collect_vec();

                    let permuter = self.perm.as_ref().unwrap().clone();
                    absorb_event.populate_iterations(
                        start_addr,
                        input_len,
                        &memory_records,
                        &permuter,
                        &mut self.p2_hash_state,
                        &mut self.p2_hash_state_cursor,
                    );

                    // Update the current hash number.
                    self.p2_current_hash_num = Some(hash_num);

                    self.record
                        .poseidon2_hash_events
                        .push(Poseidon2HashEvent::Absorb(absorb_event));

                    (a, b, c) = (a_val, b_val, c_val);
                }

                Opcode::Poseidon2Finalize => {
                    self.nb_poseidons += 1;
                    let (a_val, b_val, c_val) = self.all_rr(&instruction);

                    let p2_hash_num = a_val[0];
                    let output_ptr = b_val[0];
                    let timestamp = self.clk;

                    let do_perm = self.p2_hash_state_cursor != 0;
                    let perm_output = self.perm.as_ref().unwrap().permute(self.p2_hash_state);
                    let state = if do_perm {
                        perm_output
                    } else {
                        self.p2_hash_state
                    };
                    let output_records: [MemoryRecord<F>; DIGEST_SIZE] = array::from_fn(|i| {
                        self.mw(output_ptr + F::from_canonical_usize(i), state[i], timestamp)
                    });

                    self.record
                        .poseidon2_hash_events
                        .push(Poseidon2HashEvent::Finalize(Poseidon2FinalizeEvent {
                            clk: timestamp,
                            hash_num: p2_hash_num,
                            output_ptr,
                            output_records,
                            state_cursor: self.p2_hash_state_cursor,
                            perm_input: self.p2_hash_state,
                            perm_output,
                            previous_state: self.p2_hash_state,
                            state,
                            do_perm,
                        }));

                    self.p2_hash_state_cursor = 0;
                    self.p2_hash_state = [F::zero(); PERMUTATION_WIDTH];

                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::HintBits => {
                    self.nb_bit_decompositions += 1;
                    let (a_val, b_val, c_val) = self.all_rr(&instruction);

                    // Get the dst array ptr.
                    let dst = a_val[0].as_canonical_u32() as usize;
                    // Get the src value.
                    let num = b_val[0].as_canonical_u32();

                    // Decompose the num into LE bits.
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

                    // The timestamp for the memory reads for all of these operations will be self.clk

                    let ps_at_z_len = a_val[0];
                    let input_ptr = b_val[0];

                    let mut timestamp = self.clk;

                    // Read the input values.
                    for m in 0..ps_at_z_len.as_canonical_u32() {
                        let m = F::from_canonical_u32(m);
                        let mut ptr = input_ptr;
                        let (z_record, z) = self.mr(ptr, timestamp);
                        let z: EF = z.ext();
                        ptr += F::one();
                        let (alpha_record, alpha) = self.mr(ptr, timestamp);
                        let alpha: EF = alpha.ext();
                        ptr += F::one();
                        let (x_record, x) = self.mr(ptr, timestamp);
                        let x = x[0];
                        ptr += F::one();
                        let (log_height_record, log_height) = self.mr(ptr, timestamp);
                        let log_height = log_height[0];
                        ptr += F::one();
                        let (mat_opening_ptr_record, mat_opening_ptr) = self.mr(ptr, timestamp);
                        let mat_opening_ptr = mat_opening_ptr[0];
                        ptr += F::two();
                        let (ps_at_z_ptr_record, ps_at_z_ptr) = self.mr(ptr, timestamp);
                        let ps_at_z_ptr = ps_at_z_ptr[0];
                        ptr += F::two();
                        let (alpha_pow_ptr_record, alpha_pow_ptr) = self.mr(ptr, timestamp);
                        let alpha_pow_ptr = alpha_pow_ptr[0];
                        ptr += F::two();
                        let (ro_ptr_record, ro_ptr) = self.mr(ptr, timestamp);
                        let ro_ptr = ro_ptr[0];

                        // Get the opening values.
                        let (p_at_x_record, p_at_x) = self.mr(mat_opening_ptr + m, timestamp);
                        let p_at_x: EF = p_at_x.ext();

                        let (p_at_z_record, p_at_z) = self.mr(ps_at_z_ptr + m, timestamp);
                        let p_at_z: EF = p_at_z.ext();

                        // Calculate the quotient and update the values
                        let quotient = (-p_at_z + p_at_x) / (-z + x);

                        // Modify the ro and alpha pow values.

                        // First we peek to get the current value.
                        let (alpha_pow_ptr_plus_log_height, alpha_pow_at_log_height) =
                            self.peek(alpha_pow_ptr + log_height);
                        let alpha_pow_at_log_height: EF = alpha_pow_at_log_height.ext();

                        let (ro_ptr_plus_log_height, ro_at_log_height) =
                            self.peek(ro_ptr + log_height);
                        let ro_at_log_height: EF = ro_at_log_height.ext();

                        let new_ro_at_log_height =
                            ro_at_log_height + alpha_pow_at_log_height * quotient;
                        let new_alpha_pow_at_log_height = alpha_pow_at_log_height * alpha;

                        let ro_at_log_height_record = self.mw(
                            ro_ptr_plus_log_height,
                            Block::from(new_ro_at_log_height.as_base_slice()),
                            timestamp,
                        );

                        let alpha_pow_at_log_height_record = self.mw(
                            alpha_pow_ptr_plus_log_height,
                            Block::from(new_alpha_pow_at_log_height.as_base_slice()),
                            timestamp,
                        );

                        self.record.fri_fold_events.push(FriFoldEvent {
                            is_last_iteration: F::from_bool(
                                ps_at_z_len.as_canonical_u32() - 1 == m.as_canonical_u32(),
                            ),
                            clk: timestamp,
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
                        timestamp += F::one();
                    }

                    next_clk = timestamp;
                    (a, b, c) = (a_val, b_val, c_val);
                }
                Opcode::ExpReverseBitsLen => {
                    // Read the operands.
                    let (a_val, b_val, c_val) = self.all_rr(&instruction);

                    // A pointer to the base of the exponentiation.
                    let base = a_val[0];

                    // A pointer to the first bit (LSB) of the exponent.
                    let input_ptr = b_val[0];

                    // The length parameter in bit-reverse-len.
                    let len = c_val[0];

                    let mut timestamp = self.clk;

                    let mut accum = F::one();

                    // Read the value at the pointer `base`.
                    let mut x_record = self.mr(base, timestamp).0;

                    // Iterate over the `len` least-significant bits of the exponent.
                    for m in 0..len.as_canonical_u32() {
                        let m = F::from_canonical_u32(m);

                        // Pointer to the current bit.
                        let ptr = input_ptr + m;

                        // Read the current bit.
                        let (current_bit_record, current_bit) = self.mr(ptr, timestamp);
                        let current_bit = current_bit.ext::<EF>().as_base_slice()[0];

                        // Extract the val in `x_record`
                        let current_x_val = x_record.value[0];

                        let prev_accum = accum;
                        accum = prev_accum
                            * prev_accum
                            * if current_bit == F::one() {
                                current_x_val
                            } else {
                                F::one()
                            };

                        // On the last iteration, write accum to the address pointed to in `base`.
                        if m == len - F::one() {
                            x_record = self.mw(base, Block::from(accum), timestamp);
                        };

                        // Add the event for this iteration to the `ExecutionRecord`.
                        self.record
                            .exp_reverse_bits_len_events
                            .push(ExpReverseBitsLenEvent {
                                clk: timestamp,
                                x: x_record,
                                current_bit: current_bit_record,
                                len: len - m,
                                prev_accum,
                                accum,
                                ptr,
                                base_ptr: base,
                                iteration_num: m,
                            });
                        timestamp += F::one();
                    }

                    next_clk = timestamp;
                    (a, b, c) = (a_val, b_val, c_val);
                }
                // For both the Commit and RegisterPublicValue opcodes, we record the public value
                Opcode::Commit | Opcode::RegisterPublicValue => {
                    let (a_val, b_val, c_val) = self.all_rr(&instruction);
                    self.record.public_values.push(a_val[0]);

                    (a, b, c) = (a_val, b_val, c_val);
                }
            };

            let event = CpuEvent {
                clk: self.clk,
                pc: self.pc,
                fp: self.fp,
                instruction: instruction.clone(),
                a,
                a_record: self.access.a,
                b,
                b_record: self.access.b,
                c,
                c_record: self.access.c,
                memory_record: self.access.memory,
            };
            self.pc = next_pc;
            self.record.cpu_events.push(event);
            self.clk = next_clk;
            self.timestamp += 1;
            self.access = CpuRecord::default();

            if self.timestamp >= early_exit_ts
                || instruction.opcode == Opcode::HALT
                || instruction.opcode == Opcode::TRAP
            {
                break;
            }
        }

        let zero_block = Block::from(F::zero());
        // Collect all used memory addresses.
        for (addr, entry) in self.memory.iter() {
            // Get the initial value of the memory address from either the uninitialized memory
            // or set it as a default to 0.
            let init_value = self.uninitialized_memory.get(addr).unwrap_or(&zero_block);
            self.record
                .first_memory_record
                .push((F::from_canonical_usize(*addr), *init_value));

            self.record.last_memory_record.push((
                F::from_canonical_usize(*addr),
                entry.timestamp,
                entry.value,
            ))
        }
        self.record
            .last_memory_record
            .sort_by_key(|(addr, _, _)| *addr);

        // For all the records but the last, need to check that the next address is greater than the
        // current address, and that the difference is bounded by 2^28. We also track that the current
        // address is bounded by 2^28.
        for i in 0..self.record.last_memory_record.len() - 1 {
            self.track_addr_range_check(
                self.record.last_memory_record[i].0,
                self.record.last_memory_record[i + 1].0,
                true,
            );
            self.track_addr_range_check(F::zero(), self.record.last_memory_record[i].0, false);
        }
        // Add the last range check event for the last memory address.
        self.track_addr_range_check(
            F::zero(),
            self.record.last_memory_record.last().unwrap().0,
            false,
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use p3_field::AbstractField;
    use sp1_core::{
        stark::{RiscvAir, StarkGenericConfig},
        utils::BabyBearPoseidon2,
    };

    use super::{Instruction, Opcode, RecursionProgram, Runtime, RuntimeError};

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type A = RiscvAir<F>;

    #[test]
    fn test_witness_success() {
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

        let result = runtime.run();
        assert!(result.is_ok(), "Expected run to complete successfully");
    }

    #[test]
    fn test_witness_trap_error() {
        let zero = F::zero();
        let zero_block = [F::zero(); 4];
        let trap_program = RecursionProgram {
            traces: vec![None], // None trace for the TRAP instruction
            instructions: vec![Instruction::new(
                Opcode::TRAP,
                zero,
                zero_block,
                zero_block,
                zero,
                zero,
                false,
                false,
                "".to_string(),
            )],
        };
        let machine = A::machine(SC::default());
        let mut trap_runtime =
            Runtime::<F, EF, _>::new(&trap_program, machine.config().perm.clone());

        let trap_result = trap_runtime.run();
        assert!(
            trap_result.is_err(),
            "Expected run to return an error due to TRAP instruction"
        );

        if let Err(RuntimeError::Trap(msg)) = trap_result {
            println!("Caught expected trap error: {}", msg);
        }
    }
}
