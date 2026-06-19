use crate::{
    events::{TrapExecEvent, TrapMemInstrEvent},
    MerkleProofRecord, ShardData,
};
use deepsize2::DeepSizeOf;
use hashbrown::HashMap;
use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field, PrimeField, PrimeField32};
use slop_merkle_tree::batch_update::Tag;
use sp1_hypercube::{
    air::{
        BaseAirBuilder, InteractionScope, MachineAir, PublicValues, SP1AirBuilder,
        PROOF_NONCE_NUM_WORDS, PV_DIGEST_NUM_WORDS, SP1_PROOF_NUM_PV_ELTS,
    },
    septic_digest::SepticDigest,
    shape::Shape,
    InteractionKind, IopCtx, MachineRecord,
};
use std::{
    borrow::Borrow,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use crate::{
    events::{
        AluEvent, BranchEvent, ByteLookupEvent, ByteRecord, InstructionDecodeEvent,
        InstructionFetchEvent, JumpEvent, MemInstrEvent, MemoryLocalEvent, MemoryRecordEnum,
        PageProtLocalEvent, PrecompileEvent, PrecompileEvents, SyscallEvent, UTypeEvent,
    },
    program::Program,
    ByteOpcode, Instruction, RiscvAirId, SplitOpts, SyscallCode,
};

/// A record of the execution of a program.
///
/// The trace of the execution is represented as a list of "events" that occur every cycle.
#[derive(Clone, Debug, Serialize, Deserialize, Default, DeepSizeOf)]
pub struct ExecutionRecord {
    /// The program.
    pub program: Arc<Program>,
    /// The number of CPU related events.
    pub cpu_event_count: u32,
    /// A trace of ALU events with `rd = x0`.
    pub alu_x0_events: Vec<(AluEvent, ALUTypeRecord)>,
    /// A trace of the ADD, and ADDI events.
    pub add_events: Vec<(AluEvent, RTypeRecord)>,
    /// A trace of the ADDW events.
    pub addw_events: Vec<(AluEvent, ALUTypeRecord)>,
    /// A trace of the ADDI events.
    pub addi_events: Vec<(AluEvent, ITypeRecord)>,
    /// A trace of the MUL events.
    pub mul_events: Vec<(AluEvent, RTypeRecord)>,
    /// A trace of the SUB events.
    pub sub_events: Vec<(AluEvent, RTypeRecord)>,
    /// A trace of the SUBW events.
    pub subw_events: Vec<(AluEvent, RTypeRecord)>,
    /// A trace of the XOR, XORI, OR, ORI, AND, and ANDI events.
    pub bitwise_events: Vec<(AluEvent, ALUTypeRecord)>,
    /// A trace of the SLL and SLLI events.
    pub shift_left_events: Vec<(AluEvent, ALUTypeRecord)>,
    /// A trace of the SRL, SRLI, SRA, and SRAI events.
    pub shift_right_events: Vec<(AluEvent, ALUTypeRecord)>,
    /// A trace of the DIV, DIVU, REM, and REMU events.
    pub divrem_events: Vec<(AluEvent, RTypeRecord)>,
    /// A trace of the SLT, SLTI, SLTU, and SLTIU events.
    pub lt_events: Vec<(AluEvent, ALUTypeRecord)>,
    /// A trace of load byte instructions.
    pub memory_load_byte_events: Vec<(MemInstrEvent, ITypeRecord)>,
    /// A trace of load half instructions.
    pub memory_load_half_events: Vec<(MemInstrEvent, ITypeRecord)>,
    /// A trace of load word instructions.
    pub memory_load_word_events: Vec<(MemInstrEvent, ITypeRecord)>,
    /// A trace of load instructions with `op_a = x0`.
    pub memory_load_x0_events: Vec<(MemInstrEvent, ITypeRecord)>,
    /// A trace of load double instructions.
    pub memory_load_double_events: Vec<(MemInstrEvent, ITypeRecord)>,
    /// A trace of store byte instructions.
    pub memory_store_byte_events: Vec<(MemInstrEvent, ITypeRecord)>,
    /// A trace of store half instructions.
    pub memory_store_half_events: Vec<(MemInstrEvent, ITypeRecord)>,
    /// A trace of store word instructions.
    pub memory_store_word_events: Vec<(MemInstrEvent, ITypeRecord)>,
    /// A trace of store double instructions.
    pub memory_store_double_events: Vec<(MemInstrEvent, ITypeRecord)>,
    /// A trace of the AUIPC and LUI events.
    pub utype_events: Vec<(UTypeEvent, JTypeRecord)>,
    /// A trace of the branch events.
    pub branch_events: Vec<(BranchEvent, ITypeRecord)>,
    /// A trace of the JAL events.
    pub jal_events: Vec<(JumpEvent, JTypeRecord)>,
    /// A trace of the JALR events.
    pub jalr_events: Vec<(JumpEvent, ITypeRecord)>,
    /// A trace of the byte lookups that are needed.
    pub byte_lookups: HashMap<ByteLookupEvent, usize>,
    /// A trace of the precompile events.
    pub precompile_events: PrecompileEvents,
    /// A trace of all the shard's local memory events.
    pub cpu_local_memory_access: Vec<MemoryLocalEvent>,
    /// A trace of all the local page prot events.
    pub cpu_local_page_prot_access: Vec<PageProtLocalEvent>,
    /// A trace of all the syscall events.
    pub syscall_events: Vec<(SyscallEvent, RTypeRecord)>,
    /// A trace of all instruction fetch events.
    pub instruction_fetch_events: Vec<(InstructionFetchEvent, MemoryAccessRecord)>,
    /// A trace of all instruction decode events.
    pub instruction_decode_events: Vec<InstructionDecodeEvent>,
    /// A trace of all trap on untrusted program execution.
    pub trap_exec_events: Vec<TrapExecEvent>,
    /// A trace of all trap on load and store events.
    pub trap_load_store_events: Vec<(TrapMemInstrEvent, ITypeRecord)>,
    /// The global culmulative sum.
    pub global_cumulative_sum: Arc<Mutex<SepticDigest<u32>>>,
    /// Memory records used to bump the timestamp of the register memory access.
    pub bump_memory_events: Vec<(MemoryRecordEnum, u64, bool)>,
    /// Record where the `clk >> 24` or `pc >> 16` has incremented.
    pub bump_state_events: Vec<(u64, u64, bool, u64)>,
    /// The public values.
    pub public_values: PublicValues<u32, u64, u64, u32>,
    /// The next nonce to use for a new lookup.
    pub next_nonce: u64,
    /// The shape of the proof.
    pub shape: Option<Shape<RiscvAirId>>,
    /// The estimated total trace area of the proof.
    pub estimated_trace_area: u64,
    /// The initial timestamp of the shard.
    pub initial_timestamp: u64,
    /// The final timestamp of the shard.
    pub last_timestamp: u64,
    /// The start program counter.
    pub pc_start: Option<u64>,
    /// The final program counter.
    pub next_pc: u64,
    /// The exit code.
    pub exit_code: u32,
    /// Use optimized `generate_dependencies` for global chip.
    pub global_dependencies_opt: bool,
    /// The shard data for the core shard.
    pub shard_data: Option<ShardData>,
    /// The batch merkle proof for a merkle shard.
    pub merkle_proof_record: Option<MerkleProofRecord>,
    /// Index of the trace chunk this shard belongs to.
    pub trace_chunk_idx: u32,
    /// `0` = core (execution) shard, `1` = merkle shard.
    pub shard_kind: u32,
    /// Number of core (execution) shards in this trace chunk.
    pub num_execution_shards: u32,
    /// Number of merkle shards in this trace chunk.
    pub num_merkle_shards: u32,
    /// This shard's index within its trace chunk.
    pub shard_index: u32,
    /// Merkle root before this chunk's update, in `u32` form.
    pub prev_root: [u32; 8],
    /// Merkle root after this chunk's update, in `u32` form.
    pub cur_root: [u32; 8],
    /// The chunk's ordered global-trace commitments.
    pub global_commitments: Vec<[u32; 8]>,
}

/// `shard_kind` value for a core (execution) shard.
pub const SHARD_KIND_EXECUTION: u32 = 0;
/// `shard_kind` value for a merkle shard.
pub const SHARD_KIND_MERKLE: u32 = 1;

impl ExecutionRecord {
    /// Create a new [`ExecutionRecord`].
    #[must_use]
    pub fn new(
        program: Arc<Program>,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        global_dependencies_opt: bool,
    ) -> Self {
        let enable_untrusted_programs = program.enable_untrusted_programs as u32;
        #[cfg(feature = "mprotect")]
        let trap_context = program.trap_context;
        #[cfg(feature = "mprotect")]
        let untrusted_memory = program.untrusted_memory;

        let mut result = Self { program, ..Default::default() };
        result.public_values.proof_nonce = proof_nonce;
        result.public_values.is_untrusted_programs_enabled = enable_untrusted_programs;

        #[cfg(feature = "mprotect")]
        {
            result.public_values.enable_trap_handler = trap_context.is_some() as u32;
            result.public_values.trap_context =
                trap_context.map_or([0, 0, 0], |addr| [addr, addr + 8, addr + 16]);
            result.public_values.untrusted_memory =
                untrusted_memory.map_or([0, 0], |(start, end)| [start, end]);
        }
        result.global_dependencies_opt = global_dependencies_opt;
        result
    }

    /// Create a new [`ExecutionRecord`] with preallocated event vecs.
    #[must_use]
    pub fn new_preallocated(
        program: Arc<Program>,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        global_dependencies_opt: bool,
        reservation_size: usize,
    ) -> Self {
        let enable_untrusted_programs = program.enable_untrusted_programs;
        #[cfg(feature = "mprotect")]
        let trap_context = program.trap_context;
        #[cfg(feature = "mprotect")]
        let untrusted_memory = program.untrusted_memory;
        let mut result = Self { program, ..Default::default() };

        result.alu_x0_events.reserve(reservation_size);
        result.add_events.reserve(reservation_size);
        result.addi_events.reserve(reservation_size);
        result.addw_events.reserve(reservation_size);
        result.mul_events.reserve(reservation_size);
        result.sub_events.reserve(reservation_size);
        result.subw_events.reserve(reservation_size);
        result.bitwise_events.reserve(reservation_size);
        result.shift_left_events.reserve(reservation_size);
        result.shift_right_events.reserve(reservation_size);
        result.divrem_events.reserve(reservation_size);
        result.lt_events.reserve(reservation_size);
        result.branch_events.reserve(reservation_size);
        result.jal_events.reserve(reservation_size);
        result.jalr_events.reserve(reservation_size);
        result.utype_events.reserve(reservation_size);
        result.memory_load_x0_events.reserve(reservation_size);
        result.memory_load_byte_events.reserve(reservation_size);
        result.memory_load_half_events.reserve(reservation_size);
        result.memory_load_word_events.reserve(reservation_size);
        result.memory_load_double_events.reserve(reservation_size);
        result.memory_store_byte_events.reserve(reservation_size);
        result.memory_store_half_events.reserve(reservation_size);
        result.memory_store_word_events.reserve(reservation_size);
        result.memory_store_double_events.reserve(reservation_size);
        result.byte_lookups.reserve(reservation_size);

        result.public_values.proof_nonce = proof_nonce;
        result.public_values.is_untrusted_programs_enabled = enable_untrusted_programs as u32;
        #[cfg(feature = "mprotect")]
        {
            result.public_values.enable_trap_handler = trap_context.is_some() as u32;
            result.public_values.trap_context =
                trap_context.map_or([0, 0, 0], |addr| [addr, addr + 8, addr + 16]);
            result.public_values.untrusted_memory =
                untrusted_memory.map_or([0, 0], |(start, end)| [start, end]);
        }
        result.global_dependencies_opt = global_dependencies_opt;
        result
    }

    /// Construct an [`ExecutionRecord`] carrying a `ShardData`.
    #[must_use]
    pub fn from_shard_data(
        program: Arc<Program>,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        global_dependencies_opt: bool,
        shard_data: ShardData,
    ) -> Self {
        let mut record = Self::new(program, proof_nonce, global_dependencies_opt);
        record.shard_data = Some(shard_data);
        record
    }

    /// Record the chunk's ordered global-trace commitments.
    pub fn set_global_commitments<GC: IopCtx>(&mut self, commitments: &[GC::Digest]) {
        self.global_commitments = commitments
            .iter()
            .map(|digest| {
                let elements = GC::digest_to_elements(digest);
                std::array::from_fn(|i| elements[i].as_canonical_u32())
            })
            .collect();
    }

    /// Construct an [`ExecutionRecord`] carrying a prepared batch Merkle proof.
    #[must_use]
    pub fn from_merkle_proof_record(
        program: Arc<Program>,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        global_dependencies_opt: bool,
        merkle_proof_record: MerkleProofRecord,
    ) -> Self {
        let mut record = Self::new(program, proof_nonce, global_dependencies_opt);
        record.merkle_proof_record = Some(merkle_proof_record);
        record
    }

    /// Splits the deferred [`ExecutionRecord`] into multiple [`ExecutionRecord`]s.
    /// TODO(rkm): implement this to split up the merkle proving.
    #[allow(clippy::too_many_lines)]
    pub fn split(&mut self, _done: bool, _opts: &SplitOpts) -> Vec<ExecutionRecord> {
        Vec::new()
    }

    /// Return the number of rows needed for a chip, according to the proof shape specified in the
    /// struct.
    ///
    /// **deprecated**: TODO: remove this method.
    pub fn fixed_log2_rows<F: PrimeField, A: MachineAir<F>>(&self, _air: &A) -> Option<usize> {
        None
    }

    /// Determines whether the execution record contains CPU events.
    #[must_use]
    pub fn contains_cpu(&self) -> bool {
        self.cpu_event_count > 0
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

    /// Get all the local page prot events.
    #[inline]
    pub fn get_local_page_prot_events(&self) -> impl Iterator<Item = &PageProtLocalEvent> {
        let precompile_local_page_prot_events = self.precompile_events.get_local_page_prot_events();
        precompile_local_page_prot_events.chain(self.cpu_local_page_prot_access.iter())
    }

    /// Reset the record, without deallocating the event vecs.
    #[inline]
    pub fn reset(&mut self) {
        self.alu_x0_events.clear();
        self.add_events.clear();
        self.addw_events.clear();
        self.addi_events.clear();
        self.mul_events.clear();
        self.sub_events.clear();
        self.subw_events.clear();
        self.bitwise_events.clear();
        self.shift_left_events.clear();
        self.shift_right_events.clear();
        self.divrem_events.clear();
        self.lt_events.clear();
        self.memory_load_byte_events.clear();
        self.memory_load_half_events.clear();
        self.memory_load_word_events.clear();
        self.memory_load_x0_events.clear();
        self.memory_load_double_events.clear();
        self.memory_store_byte_events.clear();
        self.memory_store_half_events.clear();
        self.memory_store_word_events.clear();
        self.memory_store_double_events.clear();
        self.utype_events.clear();
        self.branch_events.clear();
        self.jal_events.clear();
        self.jalr_events.clear();
        self.byte_lookups.clear();
        self.precompile_events = PrecompileEvents::default();
        self.cpu_local_memory_access.clear();
        self.cpu_local_page_prot_access.clear();
        self.syscall_events.clear();
        self.instruction_fetch_events.clear();
        self.instruction_decode_events.clear();
        let mut cumulative_sum = self.global_cumulative_sum.lock().unwrap();
        *cumulative_sum = SepticDigest::default();
        self.bump_memory_events.clear();
        self.bump_state_events.clear();
        let _ = self.public_values.reset();
        self.next_nonce = 0;
        self.shape = None;
        self.estimated_trace_area = 0;
        self.initial_timestamp = 0;
        self.last_timestamp = 0;
        self.pc_start = None;
        self.next_pc = 0;
        self.exit_code = 0;
    }
}

/// A memory access record.
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize, DeepSizeOf)]
pub struct MemoryAccessRecord {
    /// The memory access of the `a` register.
    pub a: Option<MemoryRecordEnum>,
    /// The memory access of the `b` register.
    pub b: Option<MemoryRecordEnum>,
    /// The memory access of the `c` register.
    pub c: Option<MemoryRecordEnum>,
    /// The memory access of the `memory` register.
    pub memory: Option<MemoryRecordEnum>,
    /// The memory access of the untrusted instruction.
    /// If memory access for `untrusted_instruction` occurs, we also pass along the selected 32
    /// bits that is the encoded 32 bit instruction alongside the raw 64bit read
    pub untrusted_instruction: Option<(MemoryRecordEnum, u32)>,
}

/// Memory record where all three operands are registers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, DeepSizeOf)]
pub struct RTypeRecord {
    /// The a operand.
    pub op_a: u8,
    /// The register `op_a` record.
    pub a: MemoryRecordEnum,
    /// The b operand.
    pub op_b: u64,
    /// The register `op_b` record.
    pub b: MemoryRecordEnum,
    /// The c operand.
    pub op_c: u64,
    /// The register `op_c` record.
    pub c: MemoryRecordEnum,
    /// Whether the instruction is untrusted.
    pub is_untrusted: bool,
}

impl RTypeRecord {
    pub(crate) fn new(value: &MemoryAccessRecord, instruction: &Instruction) -> Self {
        Self {
            op_a: instruction.op_a,
            a: value.a.expect("expected MemoryRecord for op_a in RTypeRecord"),
            op_b: instruction.op_b,
            b: value.b.expect("expected MemoryRecord for op_b in RTypeRecord"),
            op_c: instruction.op_c,
            c: value.c.expect("expected MemoryRecord for op_c in RTypeRecord"),
            is_untrusted: value.untrusted_instruction.is_some(),
        }
    }
}
/// Memory record where the first two operands are registers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, DeepSizeOf)]
pub struct ITypeRecord {
    /// The a operand.
    pub op_a: u8,
    /// The register `op_a` record.
    pub a: MemoryRecordEnum,
    /// The b operand.
    pub op_b: u64,
    /// The register `op_b` record.
    pub b: MemoryRecordEnum,
    /// The c operand.
    pub op_c: u64,
    /// Whether the instruction is untrusted.
    pub is_untrusted: bool,
}

impl ITypeRecord {
    pub(crate) fn new(value: &MemoryAccessRecord, instruction: &Instruction) -> Self {
        debug_assert!(value.c.is_none());
        Self {
            op_a: instruction.op_a,
            a: value.a.expect("expected MemoryRecord for op_a in ITypeRecord"),
            op_b: instruction.op_b,
            b: value.b.expect("expected MemoryRecord for op_b in ITypeRecord"),
            op_c: instruction.op_c,
            is_untrusted: value.untrusted_instruction.is_some(),
        }
    }
}

/// Memory record where only one operand is a register.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, DeepSizeOf)]
pub struct JTypeRecord {
    /// The a operand.
    pub op_a: u8,
    /// The register `op_a` record.
    pub a: MemoryRecordEnum,
    /// The b operand.
    pub op_b: u64,
    /// The c operand.
    pub op_c: u64,
    /// Whether the instruction is untrusted.
    pub is_untrusted: bool,
}

impl JTypeRecord {
    pub(crate) fn new(value: &MemoryAccessRecord, instruction: &Instruction) -> Self {
        debug_assert!(value.b.is_none());
        debug_assert!(value.c.is_none());
        Self {
            op_a: instruction.op_a,
            a: value.a.expect("expected MemoryRecord for op_a in JTypeRecord"),
            op_b: instruction.op_b,
            op_c: instruction.op_c,
            is_untrusted: value.untrusted_instruction.is_some(),
        }
    }
}

/// Memory record where only the first two operands are known to be registers, but the third isn't.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, DeepSizeOf)]
pub struct ALUTypeRecord {
    /// The a operand.
    pub op_a: u8,
    /// The register `op_a` record.
    pub a: MemoryRecordEnum,
    /// The b operand.
    pub op_b: u64,
    /// The register `op_b` record.
    pub b: MemoryRecordEnum,
    /// The c operand.
    pub op_c: u64,
    /// The register `op_c` record.
    pub c: Option<MemoryRecordEnum>,
    /// Whether the instruction has an immediate.
    pub is_imm: bool,
    /// Whether the instruction is untrusted.
    pub is_untrusted: bool,
}

impl ALUTypeRecord {
    pub(crate) fn new(value: &MemoryAccessRecord, instruction: &Instruction) -> Self {
        Self {
            op_a: instruction.op_a,
            a: value.a.expect("expected MemoryRecord for op_a in ALUTypeRecord"),
            op_b: instruction.op_b,
            b: value.b.expect("expected MemoryRecord for op_b in ALUTypeRecord"),
            op_c: instruction.op_c,
            c: value.c,
            is_imm: instruction.imm_c,
            is_untrusted: value.untrusted_instruction.is_some(),
        }
    }
}

/// Memory record for an untrusted program instruction fetch.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct UntrustedProgramInstructionRecord {
    /// The a operand.
    pub memory_access_record: MemoryAccessRecord,
    /// The instruction.
    pub instruction: Instruction,
    /// The encoded instruction.
    pub encoded_instruction: u32,
}

impl MachineRecord for ExecutionRecord {
    fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("cpu_events".to_string(), self.cpu_event_count as usize);
        stats.insert("alu_x0_events".to_string(), self.alu_x0_events.len());
        stats.insert("add_events".to_string(), self.add_events.len());
        stats.insert("mul_events".to_string(), self.mul_events.len());
        stats.insert("sub_events".to_string(), self.sub_events.len());
        stats.insert("bitwise_events".to_string(), self.bitwise_events.len());
        stats.insert("shift_left_events".to_string(), self.shift_left_events.len());
        stats.insert("shift_right_events".to_string(), self.shift_right_events.len());
        stats.insert("divrem_events".to_string(), self.divrem_events.len());
        stats.insert("lt_events".to_string(), self.lt_events.len());
        stats.insert("load_byte_events".to_string(), self.memory_load_byte_events.len());
        stats.insert("load_half_events".to_string(), self.memory_load_half_events.len());
        stats.insert("load_word_events".to_string(), self.memory_load_word_events.len());
        stats.insert("load_x0_events".to_string(), self.memory_load_x0_events.len());
        stats.insert("store_byte_events".to_string(), self.memory_store_byte_events.len());
        stats.insert("store_half_events".to_string(), self.memory_store_half_events.len());
        stats.insert("store_word_events".to_string(), self.memory_store_word_events.len());
        stats.insert("branch_events".to_string(), self.branch_events.len());
        stats.insert("jal_events".to_string(), self.jal_events.len());
        stats.insert("jalr_events".to_string(), self.jalr_events.len());
        stats.insert("utype_events".to_string(), self.utype_events.len());
        stats.insert("instruction_decode_events".to_string(), self.instruction_decode_events.len());
        stats.insert("instruction_fetch_events".to_string(), self.instruction_fetch_events.len());

        for (syscall_code, events) in self.precompile_events.iter() {
            stats.insert(format!("syscall {syscall_code:?}"), events.len());
        }
        stats.insert("local_memory_access_events".to_string(), self.cpu_local_memory_access.len());
        stats.insert(
            "local_page_prot_access_events".to_string(),
            self.cpu_local_page_prot_access.len(),
        );
        if self.contains_cpu() {
            stats.insert("byte_lookups".to_string(), self.byte_lookups.len());
        }
        // Filter out the empty events.
        stats.retain(|_, v| *v != 0);
        stats
    }

    fn append(&mut self, other: &mut ExecutionRecord) {
        self.cpu_event_count += other.cpu_event_count;
        other.cpu_event_count = 0;
        self.estimated_trace_area += other.estimated_trace_area;
        other.estimated_trace_area = 0;
        self.alu_x0_events.append(&mut other.alu_x0_events);
        self.add_events.append(&mut other.add_events);
        self.sub_events.append(&mut other.sub_events);
        self.mul_events.append(&mut other.mul_events);
        self.bitwise_events.append(&mut other.bitwise_events);
        self.shift_left_events.append(&mut other.shift_left_events);
        self.shift_right_events.append(&mut other.shift_right_events);
        self.divrem_events.append(&mut other.divrem_events);
        self.lt_events.append(&mut other.lt_events);
        self.memory_load_byte_events.append(&mut other.memory_load_byte_events);
        self.memory_load_half_events.append(&mut other.memory_load_half_events);
        self.memory_load_word_events.append(&mut other.memory_load_word_events);
        self.memory_load_x0_events.append(&mut other.memory_load_x0_events);
        self.memory_store_byte_events.append(&mut other.memory_store_byte_events);
        self.memory_store_half_events.append(&mut other.memory_store_half_events);
        self.memory_store_word_events.append(&mut other.memory_store_word_events);
        self.branch_events.append(&mut other.branch_events);
        self.jal_events.append(&mut other.jal_events);
        self.jalr_events.append(&mut other.jalr_events);
        self.utype_events.append(&mut other.utype_events);
        self.syscall_events.append(&mut other.syscall_events);
        self.bump_memory_events.append(&mut other.bump_memory_events);
        self.bump_state_events.append(&mut other.bump_state_events);
        self.precompile_events.append(&mut other.precompile_events);
        self.instruction_fetch_events.append(&mut other.instruction_fetch_events);
        self.instruction_decode_events.append(&mut other.instruction_decode_events);

        if self.byte_lookups.is_empty() {
            self.byte_lookups = std::mem::take(&mut other.byte_lookups);
        } else {
            self.add_byte_lookup_events_from_maps(vec![&other.byte_lookups]);
        }
        self.cpu_local_memory_access.append(&mut other.cpu_local_memory_access);
        self.cpu_local_page_prot_access.append(&mut other.cpu_local_page_prot_access);
    }

    /// Retrieves the public values.  This method is needed for the `MachineRecord` trait, since
    fn public_values<F: AbstractField>(&self) -> Vec<F> {
        self.public_values.to_vec()
    }

    /// Constrains the public values.
    #[allow(clippy::type_complexity)]
    fn eval_public_values<AB: SP1AirBuilder>(builder: &mut AB) {
        let public_values_slice: [AB::PublicVar; SP1_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| builder.public_values()[i]);
        let public_values: &PublicValues<
            [AB::PublicVar; 4],
            [AB::PublicVar; 3],
            [AB::PublicVar; 4],
            AB::PublicVar,
        > = public_values_slice.as_slice().borrow();

        for var in public_values.empty {
            builder.assert_zero(var);
        }

        Self::eval_state(public_values, builder);
        Self::eval_first_execution_shard(public_values, builder);
        Self::eval_exit_code(public_values, builder);
        Self::eval_committed_value_digest(public_values, builder);
        Self::eval_deferred_proofs_digest(public_values, builder);
        Self::eval_merkle_root(public_values, builder);
        #[cfg(feature = "mprotect")]
        Self::eval_trap_handler(public_values, builder);
    }

    fn interactions_in_public_values() -> Vec<InteractionKind> {
        InteractionKind::all_kinds()
            .iter()
            .filter(|kind| kind.appears_in_eval_public_values())
            .copied()
            .collect()
    }

    fn global_challenge_input<GC: IopCtx>(&self) -> Option<Vec<GC::Digest>> {
        if self.global_commitments.is_empty() {
            return None;
        }
        Some(
            self.global_commitments
                .iter()
                .map(|limbs| {
                    let elements: [GC::F; 8] =
                        std::array::from_fn(|i| GC::F::from_canonical_u32(limbs[i]));
                    GC::digest_from_elements(&elements)
                })
                .collect(),
        )
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

impl ExecutionRecord {
    #[allow(clippy::type_complexity)]
    fn eval_state<AB: SP1AirBuilder>(
        public_values: &PublicValues<
            [AB::PublicVar; 4],
            [AB::PublicVar; 3],
            [AB::PublicVar; 4],
            AB::PublicVar,
        >,
        builder: &mut AB,
    ) {
        let initial_timestamp_high = public_values.initial_timestamp[1].into()
            + public_values.initial_timestamp[0].into() * AB::Expr::from_canonical_u32(1 << 8);
        let initial_timestamp_low = public_values.initial_timestamp[3].into()
            + public_values.initial_timestamp[2].into() * AB::Expr::from_canonical_u32(1 << 16);
        let last_timestamp_high = public_values.last_timestamp[1].into()
            + public_values.last_timestamp[0].into() * AB::Expr::from_canonical_u32(1 << 8);
        let last_timestamp_low = public_values.last_timestamp[3].into()
            + public_values.last_timestamp[2].into() * AB::Expr::from_canonical_u32(1 << 16);

        // Range check all the timestamp limbs.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            public_values.initial_timestamp[0].into(),
            AB::Expr::from_canonical_u32(16),
            AB::Expr::zero(),
            AB::Expr::one(),
        );
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            (public_values.initial_timestamp[3].into() - AB::Expr::one())
                * AB::F::from_canonical_u8(8).inverse(),
            AB::Expr::from_canonical_u32(13),
            AB::Expr::zero(),
            AB::Expr::one(),
        );
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            public_values.last_timestamp[0].into(),
            AB::Expr::from_canonical_u32(16),
            AB::Expr::zero(),
            AB::Expr::one(),
        );
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            (public_values.last_timestamp[3].into() - AB::Expr::one())
                * AB::F::from_canonical_u8(8).inverse(),
            AB::Expr::from_canonical_u32(13),
            AB::Expr::zero(),
            AB::Expr::one(),
        );
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
            AB::Expr::zero(),
            public_values.initial_timestamp[1],
            public_values.initial_timestamp[2],
            AB::Expr::one(),
        );
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
            AB::Expr::zero(),
            public_values.last_timestamp[1],
            public_values.last_timestamp[2],
            AB::Expr::one(),
        );

        // Range check all the initial, final program counter limbs.
        for i in 0..3 {
            builder.send_byte(
                AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
                public_values.pc_start[i].into(),
                AB::Expr::from_canonical_u32(16),
                AB::Expr::zero(),
                AB::Expr::one(),
            );
            builder.send_byte(
                AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
                public_values.next_pc[i].into(),
                AB::Expr::from_canonical_u32(16),
                AB::Expr::zero(),
                AB::Expr::one(),
            );
        }

        // Send and receive the initial and last state.
        builder.send_state(
            initial_timestamp_high.clone(),
            initial_timestamp_low.clone(),
            public_values.pc_start,
            AB::Expr::one(),
        );
        builder.receive_state(
            last_timestamp_high.clone(),
            last_timestamp_low.clone(),
            public_values.next_pc,
            AB::Expr::one(),
        );

        // If the shard is not execution shard, assert that timestamp and pc remains equal.
        let is_execution_shard = public_values.is_execution_shard.into();
        builder.assert_bool(is_execution_shard.clone());
        builder
            .when_not(is_execution_shard.clone())
            .assert_eq(initial_timestamp_low.clone(), last_timestamp_low.clone());
        builder
            .when_not(is_execution_shard.clone())
            .assert_eq(initial_timestamp_high.clone(), last_timestamp_high.clone());
        builder
            .when_not(is_execution_shard.clone())
            .assert_all_eq(public_values.pc_start, public_values.next_pc);

        // IsZeroOperation on the high bits of the timestamp.
        builder.assert_bool(public_values.is_timestamp_high_eq);
        // If high bits are equal, then `is_timestamp_high_eq == 1`.
        builder.assert_eq(
            (last_timestamp_high.clone() - initial_timestamp_high.clone())
                * public_values.inv_timestamp_high.into(),
            AB::Expr::one() - public_values.is_timestamp_high_eq.into(),
        );
        // If high bits are distinct, then `is_timestamp_high_eq == 0`.
        builder.assert_zero(
            (last_timestamp_high.clone() - initial_timestamp_high.clone())
                * public_values.is_timestamp_high_eq.into(),
        );

        // IsZeroOperation on the low bits of the timestamp.
        builder.assert_bool(public_values.is_timestamp_low_eq);
        // If low bits are equal, then `is_timestamp_low_eq == 1`.
        builder.assert_eq(
            (last_timestamp_low.clone() - initial_timestamp_low.clone())
                * public_values.inv_timestamp_low.into(),
            AB::Expr::one() - public_values.is_timestamp_low_eq.into(),
        );
        // If low bits are distinct, then `is_timestamp_low_eq == 0`.
        builder.assert_zero(
            (last_timestamp_low.clone() - initial_timestamp_low.clone())
                * public_values.is_timestamp_low_eq.into(),
        );

        // If the shard is an execution shard, then the timestamp is different.
        builder.assert_eq(
            AB::Expr::one() - is_execution_shard.clone(),
            public_values.is_timestamp_high_eq.into() * public_values.is_timestamp_low_eq.into(),
        );

        // Check that an execution shard has `last_timestamp != 1` by providing an inverse.
        // The `high + low` value cannot overflow, as they were range checked to be 24 bits.
        // `high == 1, low == 0` is impossible, as `low == 1 (mod 8)` as checked in `eval_state`.
        builder.when(is_execution_shard.clone()).assert_eq(
            (last_timestamp_high + last_timestamp_low - AB::Expr::one())
                * public_values.last_timestamp_inv.into(),
            AB::Expr::one(),
        );
    }

    #[allow(clippy::type_complexity)]
    fn eval_first_execution_shard<AB: SP1AirBuilder>(
        public_values: &PublicValues<
            [AB::PublicVar; 4],
            [AB::PublicVar; 3],
            [AB::PublicVar; 4],
            AB::PublicVar,
        >,
        builder: &mut AB,
    ) {
        // Check that `is_first_execution_shard` is boolean.
        builder.assert_bool(public_values.is_first_execution_shard.into());

        // Timestamp constraints.
        //
        // We want to assert that `is_first_execution_shard == 1` corresponds exactly to the unique
        // execution shard with initial timestamp 1.We are assuming that there is a unique
        // shard with `is_first_execution_shard == 1`. This is enforced in the verifier and
        // in recursion. Given thus, it is enough to impose that for this unique shard,
        // `initial_timestamp == 1`.
        builder.when(public_values.is_first_execution_shard.into()).assert_all_eq(
            public_values.initial_timestamp,
            [AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero(), AB::Expr::one()],
        );

        // If `is_first_execution_shard` is true, check `is_execution_shard == 1`.
        builder
            .when(public_values.is_first_execution_shard.into())
            .assert_one(public_values.is_execution_shard);

        // If `is_first_execution_shard` is true, assert the initial boundary conditions.

        // Check `prev_committed_value_digest == 0`.
        for i in 0..PV_DIGEST_NUM_WORDS {
            builder
                .when(public_values.is_first_execution_shard.into())
                .assert_all_zero(public_values.prev_committed_value_digest[i]);
        }

        // Check `prev_deferred_proofs_digest == 0`.
        builder
            .when(public_values.is_first_execution_shard.into())
            .assert_all_zero(public_values.prev_deferred_proofs_digest);

        // Check `prev_exit_code == 0`.
        builder
            .when(public_values.is_first_execution_shard.into())
            .assert_zero(public_values.prev_exit_code);

        // Check `prev_commit_syscall == 0`.
        builder
            .when(public_values.is_first_execution_shard.into())
            .assert_zero(public_values.prev_commit_syscall);

        // Check `prev_commit_deferred_syscall == 0`.
        builder
            .when(public_values.is_first_execution_shard.into())
            .assert_zero(public_values.prev_commit_deferred_syscall);
    }

    #[allow(clippy::type_complexity)]
    fn eval_exit_code<AB: SP1AirBuilder>(
        public_values: &PublicValues<
            [AB::PublicVar; 4],
            [AB::PublicVar; 3],
            [AB::PublicVar; 4],
            AB::PublicVar,
        >,
        builder: &mut AB,
    ) {
        let is_execution_shard = public_values.is_execution_shard.into();

        // If the `prev_exit_code` is non-zero, then the `exit_code` must be equal to it.
        builder.assert_zero(
            public_values.prev_exit_code.into()
                * (public_values.exit_code.into() - public_values.prev_exit_code.into()),
        );

        // If it's not an execution shard, assert that `exit_code` will not change in that shard.
        builder
            .when_not(is_execution_shard.clone())
            .assert_eq(public_values.prev_exit_code, public_values.exit_code);
    }

    #[allow(clippy::type_complexity)]
    fn eval_committed_value_digest<AB: SP1AirBuilder>(
        public_values: &PublicValues<
            [AB::PublicVar; 4],
            [AB::PublicVar; 3],
            [AB::PublicVar; 4],
            AB::PublicVar,
        >,
        builder: &mut AB,
    ) {
        let is_execution_shard = public_values.is_execution_shard.into();

        // Assert that both `prev_committed_value_digest` and `committed_value_digest` are bytes.
        for i in 0..PV_DIGEST_NUM_WORDS {
            builder.send_byte(
                AB::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                AB::Expr::zero(),
                public_values.prev_committed_value_digest[i][0],
                public_values.prev_committed_value_digest[i][1],
                AB::Expr::one(),
            );
            builder.send_byte(
                AB::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                AB::Expr::zero(),
                public_values.prev_committed_value_digest[i][2],
                public_values.prev_committed_value_digest[i][3],
                AB::Expr::one(),
            );
            builder.send_byte(
                AB::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                AB::Expr::zero(),
                public_values.committed_value_digest[i][0],
                public_values.committed_value_digest[i][1],
                AB::Expr::one(),
            );
            builder.send_byte(
                AB::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                AB::Expr::zero(),
                public_values.committed_value_digest[i][2],
                public_values.committed_value_digest[i][3],
                AB::Expr::one(),
            );
        }

        // Assert that both `prev_commit_syscall` and `commit_syscall` are boolean.
        builder.assert_bool(public_values.prev_commit_syscall);
        builder.assert_bool(public_values.commit_syscall);

        // Assert that `prev_commit_syscall == 1` implies `commit_syscall == 1`.
        builder.when(public_values.prev_commit_syscall).assert_one(public_values.commit_syscall);

        // Assert that the `commit_syscall` value doesn't change in a non-execution shard.
        builder
            .when_not(is_execution_shard.clone())
            .assert_eq(public_values.prev_commit_syscall, public_values.commit_syscall);

        // Assert that `committed_value_digest` will not change in a non-execution shard.
        for i in 0..PV_DIGEST_NUM_WORDS {
            builder.when_not(is_execution_shard.clone()).assert_all_eq(
                public_values.prev_committed_value_digest[i],
                public_values.committed_value_digest[i],
            );
        }

        // Assert that `prev_committed_value_digest != [0u8; 32]` implies `committed_value_digest`
        // must remain equal to the `prev_committed_value_digest`.
        for word in public_values.prev_committed_value_digest {
            for limb in word {
                for i in 0..PV_DIGEST_NUM_WORDS {
                    builder.when(limb).assert_all_eq(
                        public_values.prev_committed_value_digest[i],
                        public_values.committed_value_digest[i],
                    );
                }
            }
        }

        // Assert that if `prev_commit_syscall` is true, `committed_value_digest` doesn't change.
        for i in 0..PV_DIGEST_NUM_WORDS {
            builder.when(public_values.prev_commit_syscall).assert_all_eq(
                public_values.prev_committed_value_digest[i],
                public_values.committed_value_digest[i],
            );
        }
    }

    #[allow(clippy::type_complexity)]
    fn eval_deferred_proofs_digest<AB: SP1AirBuilder>(
        public_values: &PublicValues<
            [AB::PublicVar; 4],
            [AB::PublicVar; 3],
            [AB::PublicVar; 4],
            AB::PublicVar,
        >,
        builder: &mut AB,
    ) {
        let is_execution_shard = public_values.is_execution_shard.into();

        // Assert that `prev_commit_deferred_syscall` and `commit_deferred_syscall` are boolean.
        builder.assert_bool(public_values.prev_commit_deferred_syscall);
        builder.assert_bool(public_values.commit_deferred_syscall);

        // Assert that `prev_commit_deferred_syscall == 1` implies `commit_deferred_syscall == 1`.
        builder
            .when(public_values.prev_commit_deferred_syscall)
            .assert_one(public_values.commit_deferred_syscall);

        // Assert that the `commit_deferred_syscall` value doesn't change in a non-execution shard.
        builder.when_not(is_execution_shard.clone()).assert_eq(
            public_values.prev_commit_deferred_syscall,
            public_values.commit_deferred_syscall,
        );

        // Assert that `deferred_proofs_digest` will not change in a non-execution shard.
        builder.when_not(is_execution_shard.clone()).assert_all_eq(
            public_values.prev_deferred_proofs_digest,
            public_values.deferred_proofs_digest,
        );

        // Assert that `prev_deferred_proofs_digest != 0` implies `deferred_proofs_digest` must
        // remain equal to the `prev_deferred_proofs_digest`.
        for limb in public_values.prev_deferred_proofs_digest {
            builder.when(limb).assert_all_eq(
                public_values.prev_deferred_proofs_digest,
                public_values.deferred_proofs_digest,
            );
        }

        // If `prev_commit_deferred_syscall` is true, `deferred_proofs_digest` doesn't change.
        builder.when(public_values.prev_commit_deferred_syscall).assert_all_eq(
            public_values.prev_deferred_proofs_digest,
            public_values.deferred_proofs_digest,
        );
    }

    #[allow(clippy::type_complexity)]
    fn eval_merkle_root<AB: SP1AirBuilder>(
        public_values: &PublicValues<
            [AB::PublicVar; 4],
            [AB::PublicVar; 3],
            [AB::PublicVar; 4],
            AB::PublicVar,
        >,
        builder: &mut AB,
    ) {
        builder.send_merkle_traversal(
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::from_canonical_u8(Tag::InitRoot as u8),
            public_values.prev_merkle_root,
            public_values.is_first_merkle_shard,
            InteractionScope::Global,
        );

        builder.receive_merkle_traversal(
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::from_canonical_u8(Tag::FinalRoot as u8),
            public_values.merkle_root,
            public_values.is_first_merkle_shard,
            InteractionScope::Global,
        );
    }

    #[cfg(feature = "mprotect")]
    #[allow(clippy::type_complexity)]
    fn eval_trap_handler<AB: SP1AirBuilder>(
        public_values: &PublicValues<
            [AB::PublicVar; 4],
            [AB::PublicVar; 3],
            [AB::PublicVar; 4],
            AB::PublicVar,
        >,
        builder: &mut AB,
    ) {
        // `is_untrusted_programs_enabled` must be boolean.
        builder.assert_bool(public_values.is_untrusted_programs_enabled);
        // `enable_trap_handler` must be boolean.
        builder.assert_bool(public_values.enable_trap_handler);

        // If untrusted programs are not enabled, there are no trap handlers.
        builder
            .when_not(public_values.is_untrusted_programs_enabled)
            .assert_zero(public_values.enable_trap_handler);

        // The `trap_context` is with 16-bit limbs.
        // If there are no trap handlers, `trap_context` is all zero.
        for addr_idx in 0..3 {
            builder
                .when_not(public_values.enable_trap_handler)
                .assert_all_zero(public_values.trap_context[addr_idx]);
            for idx in 0..3 {
                builder.send_byte(
                    AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
                    public_values.trap_context[addr_idx][idx].into(),
                    AB::Expr::from_canonical_u32(16),
                    AB::Expr::zero(),
                    AB::Expr::one(),
                );
            }
        }

        // The `untrusted_memory` is with 16-bit limbs.
        // If untrusted programs are not enabled, `untrusted_memory` is all zero.
        for addr_idx in 0..2 {
            builder
                .when_not(public_values.is_untrusted_programs_enabled)
                .assert_all_zero(public_values.untrusted_memory[addr_idx]);
            for idx in 0..3 {
                builder.send_byte(
                    AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
                    public_values.untrusted_memory[addr_idx][idx].into(),
                    AB::Expr::from_canonical_u32(16),
                    AB::Expr::zero(),
                    AB::Expr::one(),
                );
            }
        }
    }

    /// Finalize the public values.
    pub fn finalize_public_values<F: PrimeField32>(&mut self, is_execution_shard: bool) {
        let state = &mut self.public_values;
        state.is_execution_shard = is_execution_shard as u32;

        let initial_timestamp_high = (state.initial_timestamp >> 24) as u32;
        let initial_timestamp_low = (state.initial_timestamp & 0xFFFFFF) as u32;
        let last_timestamp_high = (state.last_timestamp >> 24) as u32;
        let last_timestamp_low = (state.last_timestamp & 0xFFFFFF) as u32;

        state.initial_timestamp_inv = if state.initial_timestamp == 1 {
            0
        } else {
            F::from_canonical_u32(initial_timestamp_high + initial_timestamp_low - 1)
                .inverse()
                .as_canonical_u32()
        };

        state.last_timestamp_inv =
            F::from_canonical_u32(last_timestamp_high + last_timestamp_low - 1)
                .inverse()
                .as_canonical_u32();

        if initial_timestamp_high == last_timestamp_high {
            state.is_timestamp_high_eq = 1;
        } else {
            state.is_timestamp_high_eq = 0;
            state.inv_timestamp_high = (F::from_canonical_u32(last_timestamp_high)
                - F::from_canonical_u32(initial_timestamp_high))
            .inverse()
            .as_canonical_u32();
        }

        if initial_timestamp_low == last_timestamp_low {
            state.is_timestamp_low_eq = 1;
        } else {
            state.is_timestamp_low_eq = 0;
            state.inv_timestamp_low = (F::from_canonical_u32(last_timestamp_low)
                - F::from_canonical_u32(initial_timestamp_low))
            .inverse()
            .as_canonical_u32();
        }
        state.is_first_execution_shard = (state.initial_timestamp == 1) as u32;
    }
}
