mod instruction;
mod opcode;
mod program;
mod record;
// mod utils;

use std::array;
use std::borrow::Cow;
use std::collections::VecDeque;
use std::process::exit;
use std::{marker::PhantomData, sync::Arc};

use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
pub use instruction::*;
use itertools::Itertools;
pub use opcode::*;
use p3_field::extension::BinomialExtensionField;
use p3_poseidon2::Poseidon2;
use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
use p3_symmetric::CryptographicPermutation;
use p3_symmetric::Permutation;
pub use program::*;
pub use record::*;
// pub use utils::*;

use sp1_recursion_core::air::Block;
// use sp1_recursion_core::air::{
//     Block, RECURSION_PUBLIC_VALUES_COL_MAP, RECURSIVE_PROOF_NUM_PV_ELTS,
// };
// use sp1_recursion_core::cpu::CpuEvent;
// use sp1_recursion_core::exp_reverse_bits::ExpReverseBitsLenEvent;
// use sp1_recursion_core::fri_fold::FriFoldEvent;
// use sp1_recursion_core::memory::{compute_addr_diff, MemoryRecord};
// use sp1_recursion_core::poseidon2_wide::events::{
//     Poseidon2AbsorbEvent, Poseidon2CompressEvent, Poseidon2FinalizeEvent, Poseidon2HashEvent,
// };
// use sp1_recursion_core::range_check::{RangeCheckEvent, RangeCheckOpcode};

use p3_field::{AbstractExtensionField, ExtensionField, PrimeField32};
use sp1_core::runtime::MemoryAccessPosition;

/// TODO expand glob import
use crate::*;

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

// #[derive(Debug, Clone, Default)]
// pub struct CpuRecord<F> {
//     pub a: Option<MemoryRecord<F>>,
//     pub b: Option<MemoryRecord<F>>,
//     pub c: Option<MemoryRecord<F>>,
//     pub memory: Option<MemoryRecord<F>>,
// }

#[derive(Debug, Clone, Default)]
pub struct MemoryEntry<F> {
    pub val: Block<F>,
    pub mult: F,
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
    // pub memory: HashMap<usize, MemoryEntry<F>>,
    pub memory: HashMap<Address<F>, MemoryEntry<F>>,
    /// Uninitialized memory addresses that have a specific value they should be initialized with.
    /// The Opcodes that start with Hint* utilize this to set memory values.
    pub uninitialized_memory: HashMap<usize, Block<F>>,

    /// The execution record.
    pub record: ExecutionRecord<F>,

    /// The access record for this cycle.
    // pub access: CpuRecord<F>,
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
            // access: CpuRecord::default(),
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
            // access: CpuRecord::default(),
            witness_stream: VecDeque::new(),
            cycle_tracker: HashMap::new(),
            p2_hash_state: [F::zero(); PERMUTATION_WIDTH],
            p2_hash_state_cursor: 0,
            p2_current_hash_num: None,
            _marker: PhantomData,
        }
    }

    // pub fn print_stats(&self) {
    //     tracing::debug!("Total Cycles: {}", self.timestamp);
    //     tracing::debug!("Poseidon Operations: {}", self.nb_poseidons);
    //     tracing::debug!("Field Operations: {}", self.nb_base_ops);
    //     tracing::debug!("Extension Operations: {}", self.nb_ext_ops);
    //     tracing::debug!("Memory Operations: {}", self.nb_memory_ops);
    //     tracing::debug!("Branch Operations: {}", self.nb_branch_ops);
    //     for (name, entry) in self.cycle_tracker.iter().sorted_by_key(|(name, _)| *name) {
    //         tracing::debug!("> {}: {}", name, entry.cumulative_cycles);
    //     }
    // }

    // // Peek at the memory without touching the record.
    // fn peek(&mut self, addr: F) -> (F, Block<F>) {
    //     (
    //         addr,
    //         self.memory
    //             .get(&(addr.as_canonical_u32() as usize))
    //             .unwrap()
    //             .value,
    //     )
    // }

    // // Write to uninitialized memory.
    // fn mw_uninitialized(&mut self, addr: usize, value: Block<F>) {
    //     // Write it to uninitialized memory for creating MemoryInit table later.
    //     self.uninitialized_memory
    //         .entry(addr)
    //         .and_modify(|_| panic!("address already initialized"))
    //         .or_insert(value);
    //     // Also write it to the memory map so that it can be read later.
    //     self.memory
    //         .entry(addr)
    //         .and_modify(|_| panic!("address already initialized"))
    //         .or_insert(MemoryEntry {
    //             value,
    //             timestamp: F::zero(),
    //         });
    // }

    // /// Given a MemoryRecord event, track the range checks for the memory access.
    // /// This will be used later to set the multiplicities in the range check table.
    // fn track_memory_range_checks(&mut self, record: &MemoryRecord<F>) {
    //     let diff_16bit_limb_event = RangeCheckEvent::new(
    //         RangeCheckOpcode::U16,
    //         record.diff_16bit_limb.as_canonical_u32() as u16,
    //     );
    //     let diff_12bit_limb_event = RangeCheckEvent::new(
    //         RangeCheckOpcode::U12,
    //         record.diff_12bit_limb.as_canonical_u32() as u16,
    //     );
    //     // self.record
    //     //     .add_range_check_events(&[diff_16bit_limb_event, diff_12bit_limb_event]);
    // }

    // /// Track the range checks for the memory finalize table. This will be used later to set the
    // /// multiplicities in the range check table. The parameter `subtract_one` should be `true` when
    // /// used for checking address uniqueness, and `false` when used to range-check the addresses
    // /// themselves.
    // fn track_addr_range_check(&mut self, addr: F, next_addr: F, subtract_one: bool) {
    //     let (diff_16, diff_12) = compute_addr_diff(next_addr, addr, subtract_one);
    //     let diff_16bit_limb_event =
    //         RangeCheckEvent::new(RangeCheckOpcode::U16, diff_16.as_canonical_u32() as u16);
    //     let diff_8bit_limb_event =
    //         RangeCheckEvent::new(RangeCheckOpcode::U12, diff_12.as_canonical_u32() as u16);
    //     // self.record
    //     //     .add_range_check_events(&[diff_16bit_limb_event, diff_8bit_limb_event]);
    // }

    // fn mr(&mut self, addr: F, timestamp: F) -> (MemoryRecord<F>, Block<F>) {
    //     let entry = self
    //         .memory
    //         .entry(addr.as_canonical_u32() as usize)
    //         .or_default();
    //     let (prev_value, prev_timestamp) = (entry.value, entry.timestamp);
    //     let record = MemoryRecord::new_read(addr, prev_value, timestamp, prev_timestamp);
    //     *entry = MemoryEntry {
    //         value: prev_value,
    //         timestamp,
    //     };
    //     self.track_memory_range_checks(&record);
    //     (record, prev_value)
    // }

    // fn mr_cpu(&mut self, addr: F, position: MemoryAccessPosition) -> Block<F> {
    //     let timestamp = self.timestamp(&position);
    //     let (record, value) = self.mr(addr, timestamp);
    //     match position {
    //         MemoryAccessPosition::A => self.access.a = Some(record),
    //         MemoryAccessPosition::B => self.access.b = Some(record),
    //         MemoryAccessPosition::C => self.access.c = Some(record),
    //         MemoryAccessPosition::Memory => self.access.memory = Some(record),
    //     };
    //     value
    // }

    // fn mw(&mut self, addr: F, value: impl Into<Block<F>>, timestamp: F) -> MemoryRecord<F> {
    //     let addr_usize = addr.as_canonical_u32() as usize;
    //     let entry = self.memory.entry(addr_usize).or_default();
    //     let (prev_value, prev_timestamp) = (entry.value, entry.timestamp);
    //     let value_as_block = value.into();
    //     let record =
    //         MemoryRecord::new_write(addr, value_as_block, timestamp, prev_value, prev_timestamp);
    //     *entry = MemoryEntry {
    //         value: value_as_block,
    //         timestamp,
    //     };
    //     self.track_memory_range_checks(&record);
    //     record
    // }

    // fn mw_cpu(&mut self, addr: F, value: Block<F>, position: MemoryAccessPosition) {
    //     let timestamp = self.timestamp(&position);
    //     let record = self.mw(addr, value, timestamp);
    //     match position {
    //         MemoryAccessPosition::A => self.access.a = Some(record),
    //         MemoryAccessPosition::B => self.access.b = Some(record),
    //         MemoryAccessPosition::C => self.access.c = Some(record),
    //         MemoryAccessPosition::Memory => self.access.memory = Some(record),
    //     };
    // }

    // fn timestamp(&self, position: &MemoryAccessPosition) -> F {
    //     self.clk + F::from_canonical_u32(*position as u32)
    // }

    // // When we read the "a" position, it is never an immediate value, so we always read from memory.
    // fn get_a(&mut self, instruction: &Instruction<F>) -> Block<F> {
    //     self.mr_cpu(self.fp + instruction.op_a, MemoryAccessPosition::A)
    // }

    // // Useful to peek at the value of the "a" position without updating the access record.
    // // This assumes that there will be a write later, which is why it also returns the addr.
    // fn peek_a(&self, instruction: &Instruction<F>) -> (F, Block<F>) {
    //     let addr = self.fp + instruction.op_a;
    //     (
    //         addr,
    //         self.memory
    //             .get(&(addr.as_canonical_u32() as usize))
    //             .map(|entry| entry.value)
    //             .unwrap_or_default(),
    //     )
    // }

    // fn get_b(&mut self, instruction: &Instruction<F>) -> Block<F> {
    //     if instruction.imm_b {
    //         instruction.op_b
    //     } else {
    //         self.mr_cpu(self.fp + instruction.op_b[0], MemoryAccessPosition::B)
    //     }
    // }

    // fn get_c(&mut self, instruction: &Instruction<F>) -> Block<F> {
    //     if instruction.imm_c {
    //         instruction.op_c
    //     } else {
    //         self.mr_cpu(self.fp + instruction.op_c[0], MemoryAccessPosition::C)
    //     }
    // }

    // /// Fetch the destination address and input operand values for an ALU instruction.
    // fn alu_rr(&mut self, instruction: &Instruction<F>) -> (F, Block<F>, Block<F>) {
    //     let a_ptr = self.fp + instruction.op_a;
    //     let c_val = self.get_c(instruction);
    //     let b_val = self.get_b(instruction);

    //     (a_ptr, b_val, c_val)
    // }

    // /// Fetch the destination address input operand values for a store instruction (from stack).
    // fn mem_rr(&mut self, instruction: &Instruction<F>) -> (F, Block<F>, Block<F>) {
    //     let a_ptr = self.fp + instruction.op_a;
    //     let c_val = self.get_c(instruction);
    //     let b_val = self.get_b(instruction);

    //     (a_ptr, b_val, c_val)
    // }

    // // A function to calculate the memory address for both load and store opcodes.
    // fn calculate_address(b_val: Block<F>, c_val: Block<F>, instruction: &Instruction<F>) -> F {
    //     let index = c_val[0];
    //     let ptr = b_val[0];

    //     let offset = instruction.offset_imm;
    //     let size = instruction.size_imm;

    //     ptr + index * size + offset
    // }

    // /// Fetch the input operand values for a branch instruction.
    // fn branch_rr(&mut self, instruction: &Instruction<F>) -> (Block<F>, Block<F>, F) {
    //     let c = instruction.op_c[0];
    //     let b = self.get_b(instruction);
    //     let a = self.get_a(instruction);
    //     (a, b, c)
    // }

    // /// Read all the values for an instruction.
    // fn all_rr(&mut self, instruction: &Instruction<F>) -> (Block<F>, Block<F>, Block<F>) {
    //     let c_val = self.get_c(instruction);
    //     let b_val = self.get_b(instruction);
    //     let a_val = self.get_a(instruction);
    //     (a_val, b_val, c_val)
    // }

    /// Read from a memory address. Decrements the memory entry's mult count,
    /// removing the entry if the mult is no longer positive.
    ///
    /// # Panics
    /// Panics if the address is unassigned.
    fn mr(&mut self, addr: Address<F>) -> Cow<MemoryEntry<F>> {
        self.mr_mult(addr, F::one())
    }

    /// Read from a memory address. Reduces the memory entry's mult count by the given amount,
    /// removing the entry if the mult is no longer positive.
    ///
    /// # Panics
    /// Panics if the address is unassigned.
    fn mr_mult(&mut self, addr: Address<F>, mult: F) -> Cow<MemoryEntry<F>> {
        match self.memory.entry(addr) {
            Entry::Occupied(mut entry) => {
                let entry_mult = &mut entry.get_mut().mult;
                *entry_mult -= mult;
                // We don't check for negative mult because I'm not sure how comparison in F works.
                if entry_mult.is_zero() {
                    Cow::Owned(entry.remove())
                } else {
                    Cow::Borrowed(entry.into_mut())
                }
            }
            Entry::Vacant(_) => panic!("tried to read from unassigned address: {addr:?}",),
        }
    }

    /// Write to a memory address, setting the given value and mult.
    ///
    /// # Panics
    /// Panics if the address is already assigned.
    fn mw(&mut self, addr: Address<F>, val: Block<F>, mult: F) -> &mut MemoryEntry<F> {
        match self.memory.entry(addr) {
            Entry::Occupied(entry) => panic!("tried to write to assigned address: {entry:?}"),
            Entry::Vacant(entry) => entry.insert(MemoryEntry { val, mult }),
        }
    }

    /// Compare to [sp1_recursion_core::runtime::Runtime::run].
    pub fn run(&mut self) {
        let early_exit_ts = std::env::var("RECURSION_EARLY_EXIT_TS")
            .map_or(usize::MAX, |ts: String| ts.parse().unwrap());
        while self.pc < F::from_canonical_u32(self.program.instructions.len() as u32) {
            let idx = self.pc.as_canonical_u32() as usize;
            let instruction = self.program.instructions[idx].clone();

            let next_clk = self.clk + F::from_canonical_u32(4);
            let next_pc = self.pc + F::one();
            match instruction {
                Instruction::BaseAlu(BaseAluInstr {
                    opcode,
                    mult,
                    addrs,
                }) => {
                    self.nb_base_ops += 1;
                    // TODO better memory management like in Instruction::Mem branch
                    let in1 = self.mr(addrs.in1).val[0];
                    let in2 = self.mr(addrs.in2).val[0];
                    // Do the computation.
                    let out = match opcode {
                        Opcode::AddF => in1 + in2,
                        Opcode::SubF => in1 - in2,
                        Opcode::MulF => in1 * in2,
                        Opcode::DivF => in1 / in2,
                        _ => panic!("Invalid opcode: {:?}", opcode),
                    };
                    self.mw(addrs.out, Block::from(out), mult);
                    self.record
                        .base_alu_events
                        .push(BaseAluEvent { out, in1, in2 });
                }
                Instruction::ExtAlu(ExtAluInstr {
                    opcode,
                    mult,
                    addrs,
                }) => {
                    self.nb_ext_ops += 1;
                    // TODO better memory management like in Instruction::Mem branch
                    let in1 = self.mr(addrs.in1).val;
                    let in2 = self.mr(addrs.in2).val;
                    // Do the computation.
                    let in1_ef = EF::from_base_slice(&in1.0);
                    let in2_ef = EF::from_base_slice(&in2.0);
                    let out_ef = match opcode {
                        Opcode::AddE => in1_ef + in2_ef,
                        Opcode::SubE => in1_ef - in2_ef,
                        Opcode::MulE => in1_ef * in2_ef,
                        Opcode::DivE => in1_ef / in2_ef,
                        _ => panic!("Invalid opcode: {:?}", opcode),
                    };
                    let out = Block::from(out_ef.as_base_slice());
                    self.mw(addrs.out, out, mult);
                    self.record
                        .ext_alu_events
                        .push(ExtAluEvent { out, in1, in2 });
                }
                Instruction::Mem(MemInstr {
                    addrs: MemIo { inner: addr },
                    vals: MemIo { inner: val },
                    mult,
                    kind,
                }) => {
                    self.nb_memory_ops += 1;
                    match kind {
                        MemAccessKind::Read => {
                            let mem_entry = self.mr_mult(addr, mult);
                            assert_eq!(
                                mem_entry.val, val,
                                "stored memory value should be the specified value"
                            );
                        }
                        MemAccessKind::Write => drop(self.mw(addr, val, mult)),
                    }
                    self.record.mem_events.push(MemEvent { inner: val });
                }
            };

            // let event = CpuEvent {
            //     clk: self.clk,
            //     pc: self.pc,
            //     fp: self.fp,
            //     instruction: instruction.clone(),
            //     a,
            //     a_record: self.access.a,
            //     b,
            //     b_record: self.access.b,
            //     c,
            //     c_record: self.access.c,
            //     memory_record: self.access.memory,
            // };
            self.pc = next_pc;
            // self.record.cpu_events.push(event);
            self.clk = next_clk;
            self.timestamp += 1;
            // self.access = CpuRecord::default();

            if self.timestamp >= early_exit_ts
            // || instruction.opcode == Opcode::HALT
            // || instruction.opcode == Opcode::TRAP
            {
                break;
            }
        }

        // >>>>>>>>>>>>>>>> TODO finalize all memory that has not been read

        // let zero_block = Block::from(F::zero());
        // // Collect all used memory addresses.
        // for (addr, entry) in self.memory.iter() {
        //     // Get the initial value of the memory address from either the uninitialized memory
        //     // or set it as a default to 0.
        //     let init_value = self.uninitialized_memory.get(addr).unwrap_or(&zero_block);
        //     self.record
        //         .first_memory_record
        //         .push((F::from_canonical_usize(*addr), *init_value));

        //     // Keep the last memory record sorted by address.
        //     let pos = self
        //         .record
        //         .last_memory_record
        //         .partition_point(|(a, _, _)| *a <= F::from_canonical_usize(*addr));
        //     self.record.last_memory_record.insert(
        //         pos,
        //         (F::from_canonical_usize(*addr), entry.timestamp, entry.value),
        //     )
        // }
        // self.record
        //     .last_memory_record
        //     .sort_by_key(|(addr, _, _)| *addr);

        // // For all the records but the last, need to check that the next address is greater than the
        // // current address, and that the difference is bounded by 2^28. We also track that the current
        // // address is bounded by 2^28.
        // for i in 0..self.record.last_memory_record.len() - 1 {
        //     self.track_addr_range_check(
        //         self.record.last_memory_record[i].0,
        //         self.record.last_memory_record[i + 1].0,
        //         true,
        //     );
        //     self.track_addr_range_check(F::zero(), self.record.last_memory_record[i].0, false);
        // }
        // // Add the last range check event for the last memory address.
        // self.track_addr_range_check(
        //     F::zero(),
        //     self.record.last_memory_record.last().unwrap().0,
        //     false,
        // );
    }
}

// #[cfg(test)]
// mod tests {
//     use p3_field::AbstractField;
//     use sp1_core::{
//         stark::{RiscvAir, StarkGenericConfig},
//         utils::BabyBearPoseidon2,
//     };

//     use super::{Instruction, Opcode, RecursionProgram, Runtime};

//     type SC = BabyBearPoseidon2;
//     type F = <SC as StarkGenericConfig>::Val;
//     type EF = <SC as StarkGenericConfig>::Challenge;
//     type A = RiscvAir<F>;

//     #[test]
//     fn test_witness() {
//         let zero = F::zero();
//         let zero_block = [F::zero(); 4];
//         let program = RecursionProgram {
//             traces: vec![],
//             instructions: vec![
//                 Instruction::new(
//                     Opcode::HintLen,
//                     zero,
//                     zero_block,
//                     zero_block,
//                     zero,
//                     zero,
//                     false,
//                     false,
//                     "".to_string(),
//                 ),
//                 Instruction::new(
//                     Opcode::PrintF,
//                     zero,
//                     zero_block,
//                     zero_block,
//                     zero,
//                     zero,
//                     false,
//                     false,
//                     "".to_string(),
//                 ),
//             ],
//         };
//         let machine = A::machine(SC::default());
//         let mut runtime = Runtime::<F, EF, _>::new(&program, machine.config().perm.clone());
//         runtime.witness_stream =
//             vec![vec![F::two().into(), F::two().into(), F::two().into()]].into();
//         runtime.run();
//     }
// }
