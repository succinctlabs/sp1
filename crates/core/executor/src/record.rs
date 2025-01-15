use enum_map::EnumMap;
use hashbrown::HashMap;
use itertools::{EitherOrBoth, Itertools};
use p3_field::{AbstractField, PrimeField};
use sp1_stark::{
    air::{MachineAir, PublicValues},
    shape::Shape,
    MachineRecord, SP1CoreOpts, SplitOpts,
};
use std::{mem::take, str::FromStr, sync::Arc};

use serde::{Deserialize, Serialize};

use super::{program::Program, Opcode};
use crate::{
    events::{
        AUIPCEvent, AluEvent, BranchEvent, ByteLookupEvent, ByteRecord, CpuEvent,
        GlobalInteractionEvent, JumpEvent, MemInstrEvent, MemoryInitializeFinalizeEvent,
        MemoryLocalEvent, MemoryRecordEnum, PrecompileEvent, PrecompileEvents, SyscallEvent,
    },
    syscalls::SyscallCode,
    RiscvAirId,
};

/// A record of the execution of a program.
///
/// The trace of the execution is represented as a list of "events" that occur every cycle.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ExecutionRecord {
    /// The program.
    pub program: Arc<Program>,
    /// A trace of the CPU events which get emitted during execution.
    pub cpu_events: Vec<CpuEvent>,
    /// A trace of the ADD, and ADDI events.
    pub add_events: Vec<AluEvent>,
    /// A trace of the MUL events.
    pub mul_events: Vec<AluEvent>,
    /// A trace of the SUB events.
    pub sub_events: Vec<AluEvent>,
    /// A trace of the XOR, XORI, OR, ORI, AND, and ANDI events.
    pub bitwise_events: Vec<AluEvent>,
    /// A trace of the SLL and SLLI events.
    pub shift_left_events: Vec<AluEvent>,
    /// A trace of the SRL, SRLI, SRA, and SRAI events.
    pub shift_right_events: Vec<AluEvent>,
    /// A trace of the DIV, DIVU, REM, and REMU events.
    pub divrem_events: Vec<AluEvent>,
    /// A trace of the SLT, SLTI, SLTU, and SLTIU events.
    pub lt_events: Vec<AluEvent>,
    /// A trace of the memory instructions.
    pub memory_instr_events: Vec<MemInstrEvent>,
    /// A trace of the AUIPC events.
    pub auipc_events: Vec<AUIPCEvent>,
    /// A trace of the branch events.
    pub branch_events: Vec<BranchEvent>,
    /// A trace of the jump events.
    pub jump_events: Vec<JumpEvent>,
    /// A trace of the byte lookups that are needed.
    pub byte_lookups: HashMap<ByteLookupEvent, usize>,
    /// A trace of the precompile events.
    pub precompile_events: PrecompileEvents,
    /// A trace of the global memory initialize events.
    pub global_memory_initialize_events: Vec<MemoryInitializeFinalizeEvent>,
    /// A trace of the global memory finalize events.
    pub global_memory_finalize_events: Vec<MemoryInitializeFinalizeEvent>,
    /// A trace of all the shard's local memory events.
    pub cpu_local_memory_access: Vec<MemoryLocalEvent>,
    /// A trace of all the syscall events.
    pub syscall_events: Vec<SyscallEvent>,
    /// A trace of all the global interaction events.
    pub global_interaction_events: Vec<GlobalInteractionEvent>,
    /// The public values.
    pub public_values: PublicValues<u32, u32>,
    /// The next nonce to use for a new lookup.
    pub next_nonce: u64,
    /// The shape of the proof.
    pub shape: Option<Shape<RiscvAirId>>,
    /// The predicted counts of the proof.
    pub counts: Option<EnumMap<RiscvAirId, u64>>,
}

impl ExecutionRecord {
    /// Create a new [`ExecutionRecord`].
    #[must_use]
    pub fn new(program: Arc<Program>) -> Self {
        Self { program, ..Default::default() }
    }

    /// Add a mul event to the execution record.
    pub fn add_mul_event(&mut self, mul_event: AluEvent) {
        self.mul_events.push(mul_event);
    }

    /// Add a lt event to the execution record.
    pub fn add_lt_event(&mut self, lt_event: AluEvent) {
        self.lt_events.push(lt_event);
    }

    /// Add a batch of alu events to the execution record.
    pub fn add_alu_events(&mut self, mut alu_events: HashMap<Opcode, Vec<AluEvent>>) {
        for (opcode, value) in &mut alu_events {
            match opcode {
                Opcode::ADD => {
                    self.add_events.append(value);
                }
                Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU => {
                    self.mul_events.append(value);
                }
                Opcode::SUB => {
                    self.sub_events.append(value);
                }
                Opcode::XOR | Opcode::OR | Opcode::AND => {
                    self.bitwise_events.append(value);
                }
                Opcode::SLL => {
                    self.shift_left_events.append(value);
                }
                Opcode::SRL | Opcode::SRA => {
                    self.shift_right_events.append(value);
                }
                Opcode::SLT | Opcode::SLTU => {
                    self.lt_events.append(value);
                }
                _ => {
                    panic!("Invalid opcode: {opcode:?}");
                }
            }
        }
    }

    /// Add a memory instructions event to the execution record.
    pub fn add_memory_instructions_event(&mut self, memory_instructions_event: MemInstrEvent) {
        self.memory_instr_events.push(memory_instructions_event);
    }

    /// Add a branch event to the execution record.
    pub fn add_branch_event(&mut self, branch_event: BranchEvent) {
        self.branch_events.push(branch_event);
    }

    /// Add a jump event to the execution record.
    pub fn add_jump_event(&mut self, jump_event: JumpEvent) {
        self.jump_events.push(jump_event);
    }

    /// Add an AUIPC event to the execution record.
    pub fn add_auipc_event(&mut self, auipc_event: AUIPCEvent) {
        self.auipc_events.push(auipc_event);
    }

    /// Take out events from the [`ExecutionRecord`] that should be deferred to a separate shard.
    ///
    /// Note: we usually defer events that would increase the recursion cost significantly if
    /// included in every shard.
    #[must_use]
    pub fn defer(&mut self) -> ExecutionRecord {
        let mut execution_record = ExecutionRecord::new(self.program.clone());
        execution_record.precompile_events = std::mem::take(&mut self.precompile_events);
        execution_record.global_memory_initialize_events =
            std::mem::take(&mut self.global_memory_initialize_events);
        execution_record.global_memory_finalize_events =
            std::mem::take(&mut self.global_memory_finalize_events);
        execution_record
    }

    /// Splits the deferred [`ExecutionRecord`] into multiple [`ExecutionRecord`]s, each which
    /// contain a "reasonable" number of deferred events.
    ///
    /// The optional `last_record` will be provided if there are few enough deferred events that
    /// they can all be packed into the already existing last record.
    pub fn split(
        &mut self,
        last: bool,
        last_record: Option<&mut ExecutionRecord>,
        opts: SplitOpts,
    ) -> Vec<ExecutionRecord> {
        let mut shards = Vec::new();

        let precompile_events = take(&mut self.precompile_events);

        for (syscall_code, events) in precompile_events.into_iter() {
            let threshold = match syscall_code {
                SyscallCode::KECCAK_PERMUTE => opts.keccak,
                SyscallCode::SHA_EXTEND => opts.sha_extend,
                SyscallCode::SHA_COMPRESS => opts.sha_compress,
                _ => opts.deferred,
            };

            let chunks = events.chunks_exact(threshold);
            if last {
                let remainder = chunks.remainder().to_vec();
                if !remainder.is_empty() {
                    let mut execution_record = ExecutionRecord::new(self.program.clone());
                    execution_record.precompile_events.insert(syscall_code, remainder);
                    shards.push(execution_record);
                }
            } else {
                self.precompile_events.insert(syscall_code, chunks.remainder().to_vec());
            }
            let mut event_shards = chunks
                .map(|chunk| {
                    let mut execution_record = ExecutionRecord::new(self.program.clone());
                    execution_record.precompile_events.insert(syscall_code, chunk.to_vec());
                    execution_record
                })
                .collect::<Vec<_>>();
            shards.append(&mut event_shards);
        }

        if last {
            self.global_memory_initialize_events.sort_by_key(|event| event.addr);
            self.global_memory_finalize_events.sort_by_key(|event| event.addr);

            // If there are no precompile shards, and `last_record` is Some, pack the memory events
            // into the last record.
            let pack_memory_events_into_last_record = last_record.is_some() && shards.is_empty();
            let mut blank_record = ExecutionRecord::new(self.program.clone());

            // If `last_record` is None, use a blank record to store the memory events.
            let last_record_ref = if pack_memory_events_into_last_record {
                last_record.unwrap()
            } else {
                &mut blank_record
            };

            let mut init_addr_bits = [0; 32];
            let mut finalize_addr_bits = [0; 32];
            for mem_chunks in self
                .global_memory_initialize_events
                .chunks(opts.memory)
                .zip_longest(self.global_memory_finalize_events.chunks(opts.memory))
            {
                let (mem_init_chunk, mem_finalize_chunk) = match mem_chunks {
                    EitherOrBoth::Both(mem_init_chunk, mem_finalize_chunk) => {
                        (mem_init_chunk, mem_finalize_chunk)
                    }
                    EitherOrBoth::Left(mem_init_chunk) => (mem_init_chunk, [].as_slice()),
                    EitherOrBoth::Right(mem_finalize_chunk) => ([].as_slice(), mem_finalize_chunk),
                };
                last_record_ref.global_memory_initialize_events.extend_from_slice(mem_init_chunk);
                last_record_ref.public_values.previous_init_addr_bits = init_addr_bits;
                if let Some(last_event) = mem_init_chunk.last() {
                    let last_init_addr_bits = core::array::from_fn(|i| (last_event.addr >> i) & 1);
                    init_addr_bits = last_init_addr_bits;
                }
                last_record_ref.public_values.last_init_addr_bits = init_addr_bits;

                last_record_ref.global_memory_finalize_events.extend_from_slice(mem_finalize_chunk);
                last_record_ref.public_values.previous_finalize_addr_bits = finalize_addr_bits;
                if let Some(last_event) = mem_finalize_chunk.last() {
                    let last_finalize_addr_bits =
                        core::array::from_fn(|i| (last_event.addr >> i) & 1);
                    finalize_addr_bits = last_finalize_addr_bits;
                }
                last_record_ref.public_values.last_finalize_addr_bits = finalize_addr_bits;

                if !pack_memory_events_into_last_record {
                    // If not packing memory events into the last record, add 'last_record_ref'
                    // to the returned records. `take` replaces `blank_program` with the default.
                    shards.push(take(last_record_ref));

                    // Reset the last record so its program is the correct one. (The default program
                    // provided by `take` contains no instructions.)
                    last_record_ref.program = self.program.clone();
                }
            }
        }
        shards
    }

    /// Return the number of rows needed for a chip, according to the proof shape specified in the
    /// struct.
    pub fn fixed_log2_rows<F: PrimeField, A: MachineAir<F>>(&self, air: &A) -> Option<usize> {
        self.shape.as_ref().map(|shape| {
            shape
                .log2_height(&RiscvAirId::from_str(&air.name()).unwrap())
                .unwrap_or_else(|| panic!("Chip {} not found in specified shape", air.name()))
        })
    }

    /// Determines whether the execution record contains CPU events.
    #[must_use]
    pub fn contains_cpu(&self) -> bool {
        !self.cpu_events.is_empty()
    }

    #[inline]
    /// Add a precompile event to the execution record.
    pub fn add_precompile_event(
        &mut self,
        syscall_code: SyscallCode,
        syscall_event: SyscallEvent,
        event: PrecompileEvent,
    ) {
        self.precompile_events.add_event(syscall_code, syscall_event, event);
    }

    /// Get all the precompile events for a syscall code.
    #[inline]
    #[must_use]
    pub fn get_precompile_events(
        &self,
        syscall_code: SyscallCode,
    ) -> &Vec<(SyscallEvent, PrecompileEvent)> {
        self.precompile_events.get_events(syscall_code).expect("Precompile events not found")
    }

    /// Get all the local memory events.
    #[inline]
    pub fn get_local_mem_events(&self) -> impl Iterator<Item = &MemoryLocalEvent> {
        let precompile_local_mem_events = self.precompile_events.get_local_mem_events();
        precompile_local_mem_events.chain(self.cpu_local_memory_access.iter())
    }
}

/// A memory access record.
#[derive(Debug, Copy, Clone, Default)]
pub struct MemoryAccessRecord {
    /// The memory access of the `a` register.
    pub a: Option<MemoryRecordEnum>,
    /// The memory access of the `b` register.
    pub b: Option<MemoryRecordEnum>,
    /// The memory access of the `c` register.
    pub c: Option<MemoryRecordEnum>,
    /// The memory access of the `memory` register.
    pub memory: Option<MemoryRecordEnum>,
}

impl MachineRecord for ExecutionRecord {
    type Config = SP1CoreOpts;

    fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("cpu_events".to_string(), self.cpu_events.len());
        stats.insert("add_events".to_string(), self.add_events.len());
        stats.insert("mul_events".to_string(), self.mul_events.len());
        stats.insert("sub_events".to_string(), self.sub_events.len());
        stats.insert("bitwise_events".to_string(), self.bitwise_events.len());
        stats.insert("shift_left_events".to_string(), self.shift_left_events.len());
        stats.insert("shift_right_events".to_string(), self.shift_right_events.len());
        stats.insert("divrem_events".to_string(), self.divrem_events.len());
        stats.insert("lt_events".to_string(), self.lt_events.len());
        stats.insert("memory_instructions_events".to_string(), self.memory_instr_events.len());
        stats.insert("branch_events".to_string(), self.branch_events.len());
        stats.insert("jump_events".to_string(), self.jump_events.len());
        stats.insert("auipc_events".to_string(), self.auipc_events.len());

        for (syscall_code, events) in self.precompile_events.iter() {
            stats.insert(format!("syscall {syscall_code:?}"), events.len());
        }

        stats.insert(
            "global_memory_initialize_events".to_string(),
            self.global_memory_initialize_events.len(),
        );
        stats.insert(
            "global_memory_finalize_events".to_string(),
            self.global_memory_finalize_events.len(),
        );
        stats.insert("local_memory_access_events".to_string(), self.cpu_local_memory_access.len());
        if !self.cpu_events.is_empty() {
            stats.insert("byte_lookups".to_string(), self.byte_lookups.len());
        }
        // Filter out the empty events.
        stats.retain(|_, v| *v != 0);
        stats
    }

    fn append(&mut self, other: &mut ExecutionRecord) {
        self.cpu_events.append(&mut other.cpu_events);
        self.add_events.append(&mut other.add_events);
        self.sub_events.append(&mut other.sub_events);
        self.mul_events.append(&mut other.mul_events);
        self.bitwise_events.append(&mut other.bitwise_events);
        self.shift_left_events.append(&mut other.shift_left_events);
        self.shift_right_events.append(&mut other.shift_right_events);
        self.divrem_events.append(&mut other.divrem_events);
        self.lt_events.append(&mut other.lt_events);
        self.memory_instr_events.append(&mut other.memory_instr_events);
        self.branch_events.append(&mut other.branch_events);
        self.jump_events.append(&mut other.jump_events);
        self.auipc_events.append(&mut other.auipc_events);
        self.syscall_events.append(&mut other.syscall_events);

        self.precompile_events.append(&mut other.precompile_events);

        if self.byte_lookups.is_empty() {
            self.byte_lookups = std::mem::take(&mut other.byte_lookups);
        } else {
            self.add_byte_lookup_events_from_maps(vec![&other.byte_lookups]);
        }

        self.global_memory_initialize_events.append(&mut other.global_memory_initialize_events);
        self.global_memory_finalize_events.append(&mut other.global_memory_finalize_events);
        self.cpu_local_memory_access.append(&mut other.cpu_local_memory_access);
        self.global_interaction_events.append(&mut other.global_interaction_events);
    }

    /// Retrieves the public values.  This method is needed for the `MachineRecord` trait, since
    fn public_values<F: AbstractField>(&self) -> Vec<F> {
        self.public_values.to_vec()
    }
}

impl ByteRecord for ExecutionRecord {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        *self.byte_lookups.entry(blu_event).or_insert(0) += 1;
    }

    #[inline]
    fn add_byte_lookup_events_from_maps(
        &mut self,
        new_events: Vec<&HashMap<ByteLookupEvent, usize>>,
    ) {
        for new_blu_map in new_events {
            for (blu_event, count) in new_blu_map.iter() {
                *self.byte_lookups.entry(*blu_event).or_insert(0) += count;
            }
        }
    }
}
