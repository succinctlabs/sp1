use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use hashbrown::HashMap;
use powdr_autoprecompiles::execution::ApcCall;
use sp1_hypercube::air::{PublicValues, PROOF_NONCE_NUM_WORDS};
use sp1_jit::MinimalTrace;
use sp1_primitives::consts::PAGE_SIZE;

use crate::{
    autoprecompiles::ExecutionRecordSnapshot,
    events::{
        AluEvent, BranchEvent, InstructionDecodeEvent, InstructionFetchEvent, IntoMemoryRecord,
        JumpEvent, MemInstrEvent, MemoryAccessPosition, MemoryLocalEvent, MemoryReadRecord,
        MemoryRecord, MemoryRecordEnum, MemoryWriteRecord, PageProtLocalEvent, PageProtRecord,
        PrecompileEvent, SyscallEvent, TrapExecEvent, TrapMemInstrEvent, UTypeEvent,
    },
    vm::{
        results::{
            AluResult, BranchResult, CycleResult, EcallResult, FetchResult, JumpResult, LoadResult,
            LoadResultSupervisor, MaybeImmediate, StoreResult, StoreResultSupervisor, TrapResult,
            UTypeResult,
        },
        syscall::SyscallRuntime,
        CoreVM,
    },
    ALUTypeRecord, ExecutionError, ExecutionMode, ExecutionRecord, ITypeRecord, Instruction,
    JTypeRecord, MemoryAccessRecord, Opcode, Program, RTypeRecord, Register, SP1CoreOpts,
    SupervisorMode, SyscallCode, TrapError, UserMode,
};

/// A RISC-V VM that uses a [`MinimalTrace`] to create a [`ExecutionRecord`].
///
/// The type parameter `M` determines whether page protection checks are enabled.
pub struct TracingVM<'a, M: ExecutionMode> {
    /// The core VM.
    pub core: CoreVM<'a, M, ExecutionRecordSnapshot>,
    /// The local memory access for the CPU.
    pub local_memory_access: LocalMemoryAccess,
    /// The local page prot access for the CPU.
    pub local_page_prot_access: LocalPageProtAccess,
    /// The local memory access for any deferred precompiles.
    pub precompile_local_memory_access: Option<LocalMemoryAccess>,
    /// The local page prot access for any deferred precompiles.
    pub precompile_local_page_prot_access: Option<LocalPageProtAccess>,
    /// Decoded instruction events.
    pub decoded_instruction_events: HashMap<u32, InstructionDecodeEvent>,
    /// The execution record were populating.
    pub record: &'a mut ExecutionRecord,
    /// The shard's full memory-read oracle, retained so per-APC blocks can be sliced out for their
    /// [`ApcInvocation`] (or replayed on abort). Captured once at construction. Empty when there
    /// are no APCs (skip gate inert) or on a replay VM.
    shard_reads: Arc<[sp1_jit::MemValue]>,
    /// Pre-state captured at each APC-start fetch, keyed by `(apc_id, entry cpu_event_count)`.
    /// `cpu_event_count` is monotonic, so the key uniquely identifies the entry; a successful
    /// `ApcCall` later looks itself up by `(apc_id, from.cpu_event_count)`.
    apc_pre_states: HashMap<(usize, u32), CoreEntryState>,
    /// Static map, indexed by `pc_idx`, of the APC id whose range contains that PC (`None` outside
    /// any range). `is_some()` is the "inside an APC range" test; the id attributes skipped
    /// instructions to their block. Empty on a replay VM.
    apc_id_by_pc_idx: Arc<Vec<Option<usize>>>,
    /// The APC invocation whose instructions are currently being skipped in this shard (`None`
    /// when not inside a skipped block). At most one invocation is in progress at a time: APC
    /// blocks execute contiguously, so a new APC start means the previous invocation resolved.
    /// Tracked per-invocation (by `(apc_id, key_clk)`) so loops are correct. Resolution:
    ///  - success → cleared on its `ApcCall` (the APC chip regenerates its rows via re-execution);
    ///  - range-exit (execution left the APC's static range without a call — abort / branch-out /
    ///    bump / optimistic-constraint failure) → flushed as software the moment the PC leaves;
    ///  - loop re-entry (a fresh APC start before the range-exit fired) → flushed before its
    ///    pre-state is clobbered;
    ///  - segmentation → still in progress at shard end, flushed in `flush_aborted_blocks`.
    ///
    /// The per-cycle gate is active iff the current PC's `apc_id` matches `current_skip`.
    current_skip: Option<CurrentSkip>,
    /// Register epoch-crossing bumps collected during the in-progress skip block. Committed to
    /// `record.bump_memory_events` (→ shared `MemoryBump` chip) iff the block SUCCEEDS as an APC;
    /// discarded on abort (the flush replay re-emits them as software), so a block that crosses an
    /// epoch *and* aborts for another reason never double-counts the bump.
    pending_register_bumps: Vec<(MemoryRecordEnum, u64, bool)>,
    /// Phantom data for the execution mode.
    _mode: PhantomData<M>,
}

/// Step exactly one instruction. Implemented for each concrete [`ExecutionMode`] so the
/// mode-generic record-in-chip replay path ([`TracingVM::replay_block_into`]) can drive the
/// mode's own `execute_instruction` (which differs between Supervisor and User modes).
pub trait StepInstruction {
    /// Step exactly one instruction (mode-specific `execute_instruction`).
    fn step_instruction(&mut self) -> Result<CycleResult, ExecutionError>;
}

impl StepInstruction for TracingVM<'_, SupervisorMode> {
    fn step_instruction(&mut self) -> Result<CycleResult, ExecutionError> {
        self.execute_instruction()
    }
}

impl StepInstruction for TracingVM<'_, UserMode> {
    fn step_instruction(&mut self) -> Result<CycleResult, ExecutionError> {
        self.execute_instruction()
    }
}

/// An APC invocation currently being skipped ([`TracingVM::current_skip`]).
#[derive(Clone, Copy)]
struct CurrentSkip {
    /// The APC id of the block being skipped.
    apc_id: usize,
    /// `cpu_event_count` at the block's entry — the per-invocation key into `apc_pre_states`.
    key_clk: u32,
    /// Number of this invocation's instructions skipped so far in this shard.
    count: usize,
}

/// Pre-state captured at an APC block's entry, used to build its [`ApcInvocation`] (for a
/// successful candidate) or to re-execute the block as software (for an aborted candidate).
#[derive(Clone)]
struct CoreEntryState {
    registers: [MemoryRecord; 32],
    pc: u64,
    clk: u64,
    global_clk: u64,
    /// Read-oracle position at block entry, so the block's read slice can be sliced from
    /// `shard_reads` for re-execution on abort.
    mem_reads_remaining: usize,
}

impl TracingVM<'_, SupervisorMode> {
    /// Execute the program until it halts.
    pub fn execute(&mut self) -> Result<CycleResult, ExecutionError> {
        if self.core.is_done() {
            return Ok(CycleResult::Done(true));
        }

        loop {
            match self.execute_instruction()? {
                // Continue executing the program.
                CycleResult::Done(false) => {}
                CycleResult::TraceEnd => {
                    self.register_refresh();
                    self.postprocess();
                    return Ok(CycleResult::ShardBoundary);
                }
                CycleResult::Done(true) => {
                    self.postprocess();
                    return Ok(CycleResult::Done(true));
                }
                CycleResult::ShardBoundary => {
                    unreachable!("Shard boundary should never be returned for tracing VM")
                }
            }
        }
    }

    /// Execute the next instruction at the current PC.
    pub fn execute_instruction(&mut self) -> Result<CycleResult, ExecutionError> {
        let pc = self.core.pc();

        // Record-in-chip: resolve prior aborts, capture entry pre-state, begin skip invocation.
        let apc_id = self.begin_cycle();

        // The snapshot callback is invoked lazily inside `fetch` only when an APC candidate
        // is being inserted; cloning the record snapshot here is acceptable in that path.
        let instruction = self.core.fetch(|| self.record.snapshot());

        // Record-in-chip: suppress per-opcode emission while an APC block is in progress.
        self.set_skip_gate(apc_id);

        let mr_record = None;

        match &instruction.opcode {
            Opcode::ADD
            | Opcode::ADDI
            | Opcode::SUB
            | Opcode::XOR
            | Opcode::OR
            | Opcode::AND
            | Opcode::SLL
            | Opcode::SLLW
            | Opcode::SRL
            | Opcode::SRA
            | Opcode::SRLW
            | Opcode::SRAW
            | Opcode::SLT
            | Opcode::SLTU
            | Opcode::MUL
            | Opcode::MULHU
            | Opcode::MULHSU
            | Opcode::MULH
            | Opcode::MULW
            | Opcode::DIVU
            | Opcode::REMU
            | Opcode::DIV
            | Opcode::REM
            | Opcode::DIVW
            | Opcode::ADDW
            | Opcode::SUBW
            | Opcode::DIVUW
            | Opcode::REMUW
            | Opcode::REMW => {
                self.execute_alu(&instruction, mr_record.as_ref(), pc);
            }
            Opcode::LB
            | Opcode::LBU
            | Opcode::LH
            | Opcode::LHU
            | Opcode::LW
            | Opcode::LWU
            | Opcode::LD => self.execute_load(&instruction, mr_record.as_ref(), pc)?,
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => {
                self.execute_store(&instruction, mr_record.as_ref(), pc)?;
            }
            Opcode::JAL | Opcode::JALR => {
                self.execute_jump(&instruction, mr_record.as_ref(), pc);
            }
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                self.execute_branch(&instruction, mr_record.as_ref(), pc);
            }
            Opcode::LUI | Opcode::AUIPC => {
                self.execute_utype(&instruction, mr_record.as_ref(), pc);
            }
            Opcode::ECALL => self.execute_ecall(&instruction, mr_record.as_ref(), pc)?,
            Opcode::EBREAK | Opcode::UNIMP => {
                unreachable!("Invalid opcode for `execute_instruction`: {:?}", instruction.opcode)
            }
        }

        self.core.check_bump(&instruction);

        // Record-in-chip: post-block read-oracle cursor for the `to` snapshot.
        if self.capturing() {
            self.record.mem_reads_remaining = self.core.mem_reads.len();
        }

        let (res, calls) = self.core.advance(|| self.record.snapshot());
        self.end_cycle_capture(&calls);
        self.record.apply_calls(&calls);

        Ok(res)
    }
}

impl TracingVM<'_, SupervisorMode> {
    /// Execute a load instruction.
    pub fn execute_load(
        &mut self,
        instruction: &Instruction,
        untrusted_instruction_record: Option<&MemoryReadRecord>,
        pc: u64,
    ) -> Result<(), ExecutionError> {
        let LoadResultSupervisor { mut a, b, c, rs1, rd, addr, rr_record, rw_record, mr_record } =
            self.core.execute_load(instruction)?;

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(rw_record)),
            b: Some(MemoryRecordEnum::Read(rr_record)),
            c: None,
            memory: Some(MemoryRecordEnum::Read(mr_record)),
            untrusted_instruction: untrusted_instruction_record
                .map(|&record| (record.into(), (record.value >> (pc % 8 * 8)) as u32)),
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.local_memory_access.insert_record(rd as u64, rw_record);
        self.local_memory_access.insert_record(rs1 as u64, rr_record);
        self.local_memory_access.insert_record(addr & !0b111, mr_record);

        if let Some(untrusted_instruction_record) = untrusted_instruction_record {
            self.local_memory_access.insert_record(pc & !0b111, *untrusted_instruction_record);
            self.local_page_prot_access.insert_record(
                pc / PAGE_SIZE as u64,
                untrusted_instruction_record.prev_page_prot_record.unwrap(),
                self.core.clk(),
                untrusted_instruction_record.prev_page_prot_record.unwrap().page_prot,
            );
        }

        self.emit_mem_instr_event(instruction, a, b, c, &mem_access_record, op_a_0);

        self.emit_events(
            self.core.clk(),
            self.core.next_pc(),
            false,
            false,
            instruction,
            &mem_access_record,
            0,
        );

        Ok(())
    }

    /// Execute a store instruction.
    fn execute_store(
        &mut self,
        instruction: &Instruction,
        untrusted_instruction_record: Option<&MemoryReadRecord>,
        pc: u64,
    ) -> Result<(), ExecutionError> {
        let StoreResultSupervisor {
            mut a,
            b,
            c,
            rs1,
            rs2,
            addr,
            rs1_record,
            rs2_record,
            mw_record,
        } = self.core.execute_store(instruction)?;

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Read(rs1_record)),
            b: Some(MemoryRecordEnum::Read(rs2_record)),
            c: None,
            memory: Some(MemoryRecordEnum::Write(mw_record)),
            untrusted_instruction: untrusted_instruction_record
                .map(|&record| (record.into(), (record.value >> (pc % 8 * 8)) as u32)),
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.local_memory_access.insert_record(addr & !0b111, mw_record);
        self.local_memory_access.insert_record(rs1 as u64, rs1_record);
        self.local_memory_access.insert_record(rs2 as u64, rs2_record);
        if let Some(untrusted_instruction_record) = untrusted_instruction_record {
            self.local_memory_access.insert_record(pc & !0b111, *untrusted_instruction_record);
            self.local_page_prot_access.insert_record(
                pc / PAGE_SIZE as u64,
                untrusted_instruction_record.prev_page_prot_record.unwrap(),
                self.core.clk(),
                untrusted_instruction_record.prev_page_prot_record.unwrap().page_prot,
            );
        }

        self.emit_mem_instr_event(instruction, a, b, c, &mem_access_record, op_a_0);

        self.emit_events(
            self.core.clk(),
            self.core.next_pc(),
            false,
            false,
            instruction,
            &mem_access_record,
            0,
        );

        Ok(())
    }
}

impl TracingVM<'_, UserMode> {
    /// Execute the program until it halts.
    pub fn execute(&mut self) -> Result<CycleResult, ExecutionError> {
        if self.core.is_done() {
            return Ok(CycleResult::Done(true));
        }

        loop {
            match self.execute_instruction()? {
                CycleResult::Done(false) => {}
                CycleResult::TraceEnd => {
                    self.register_refresh();
                    self.postprocess();
                    return Ok(CycleResult::ShardBoundary);
                }
                CycleResult::Done(true) => {
                    self.postprocess();
                    return Ok(CycleResult::Done(true));
                }
                CycleResult::ShardBoundary => {
                    unreachable!("Shard boundary should never be returned for tracing VM")
                }
            }
        }
    }

    /// Execute the next instruction at the current PC.
    fn execute_instruction(&mut self) -> Result<CycleResult, ExecutionError> {
        // Record-in-chip: resolve prior aborts, capture entry pre-state, begin skip invocation.
        // (Untrusted / trap-fetch instructions are never inside an APC range, so the gate stays
        // inert on the trap path below — `apc_id` is `None` there.)
        let apc_id = self.begin_cycle();

        let FetchResult { instruction, mr_record, pc, error } =
            self.core.fetch(|| self.record.snapshot())?;

        // Record-in-chip: suppress per-opcode emission while an APC block is in progress.
        self.set_skip_gate(apc_id);

        if let Some(error) = error {
            let trap_result = self.handle_error(error)?;
            assert!(
                mr_record.is_some(),
                "if an error occurred fetching an instruction, it must be an untrusted instruction"
            );
            let page_prot_record = mr_record.unwrap().prev_page_prot_record.unwrap();
            self.local_page_prot_access.insert_record(
                pc / PAGE_SIZE as u64,
                page_prot_record,
                self.core.clk(),
                page_prot_record.page_prot,
            );

            self.emit_trap_exec_event(trap_result, page_prot_record);
            self.emit_trap_events(self.core.clk(), self.core.next_pc());
            if self.capturing() {
                self.record.mem_reads_remaining = self.core.mem_reads.len();
            }
            let (res, calls) = self.core.advance(|| self.record.snapshot());
            self.end_cycle_capture(&calls);
            self.record.apply_calls(&calls);
            return Ok(res);
        }

        if instruction.is_none() {
            unreachable!("Fetching the next instruction failed");
        }

        // SAFETY: The instruction is guaranteed to be valid as we checked for `is_none` above.
        let instruction = unsafe { instruction.unwrap_unchecked() };

        match &instruction.opcode {
            Opcode::ADD
            | Opcode::ADDI
            | Opcode::SUB
            | Opcode::XOR
            | Opcode::OR
            | Opcode::AND
            | Opcode::SLL
            | Opcode::SLLW
            | Opcode::SRL
            | Opcode::SRA
            | Opcode::SRLW
            | Opcode::SRAW
            | Opcode::SLT
            | Opcode::SLTU
            | Opcode::MUL
            | Opcode::MULHU
            | Opcode::MULHSU
            | Opcode::MULH
            | Opcode::MULW
            | Opcode::DIVU
            | Opcode::REMU
            | Opcode::DIV
            | Opcode::REM
            | Opcode::DIVW
            | Opcode::ADDW
            | Opcode::SUBW
            | Opcode::DIVUW
            | Opcode::REMUW
            | Opcode::REMW => {
                self.execute_alu(&instruction, mr_record.as_ref(), pc);
            }
            Opcode::LB
            | Opcode::LBU
            | Opcode::LH
            | Opcode::LHU
            | Opcode::LW
            | Opcode::LWU
            | Opcode::LD => self.execute_load(&instruction, mr_record.as_ref(), pc)?,
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => {
                self.execute_store(&instruction, mr_record.as_ref(), pc)?;
            }
            Opcode::JAL | Opcode::JALR => {
                self.execute_jump(&instruction, mr_record.as_ref(), pc);
            }
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                self.execute_branch(&instruction, mr_record.as_ref(), pc);
            }
            Opcode::LUI | Opcode::AUIPC => {
                self.execute_utype(&instruction, mr_record.as_ref(), pc);
            }
            Opcode::ECALL => self.execute_ecall(&instruction, mr_record.as_ref(), pc)?,
            Opcode::EBREAK | Opcode::UNIMP => {
                unreachable!("Invalid opcode for `execute_instruction`: {:?}", instruction.opcode)
            }
        }

        // Record-in-chip: post-block read-oracle cursor for the `to` snapshot.
        if self.capturing() {
            self.record.mem_reads_remaining = self.core.mem_reads.len();
        }

        let (res, calls) = self.core.advance(|| self.record.snapshot());
        self.end_cycle_capture(&calls);
        self.record.apply_calls(&calls);
        Ok(res)
    }
}

impl TracingVM<'_, UserMode> {
    /// Execute a load instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the load instruction.
    pub fn execute_load(
        &mut self,
        instruction: &Instruction,
        untrusted_instruction_record: Option<&MemoryReadRecord>,
        pc: u64,
    ) -> Result<(), ExecutionError> {
        let LoadResult { mut a, b, c, rs1, rd, addr, rr_record, rw_record, mr_record, error } =
            self.core.execute_load(instruction)?;

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(rw_record)),
            b: Some(MemoryRecordEnum::Read(rr_record)),
            c: None,
            memory: Some(MemoryRecordEnum::Read(mr_record)),
            untrusted_instruction: untrusted_instruction_record
                .map(|&record| (record.into(), (record.value >> (pc % 8 * 8)) as u32)),
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.local_memory_access.insert_record(rd as u64, rw_record);
        self.local_memory_access.insert_record(rs1 as u64, rr_record);
        if error.is_none() {
            self.local_memory_access.insert_record(addr & !0b111, mr_record);
        }

        if let Some(untrusted_instruction_record) = untrusted_instruction_record {
            self.local_memory_access.insert_record(pc & !0b111, *untrusted_instruction_record);
            self.local_page_prot_access.insert_record(
                pc / PAGE_SIZE as u64,
                untrusted_instruction_record.prev_page_prot_record.unwrap(),
                self.core.clk(),
                untrusted_instruction_record.prev_page_prot_record.unwrap().page_prot,
            );
        }

        self.local_page_prot_access.insert_record(
            addr / PAGE_SIZE as u64,
            mr_record.prev_page_prot_record.unwrap(),
            self.core.clk() + MemoryAccessPosition::Memory as u64,
            mr_record.prev_page_prot_record.unwrap().page_prot,
        );

        let is_trap = error.is_some();
        if let Some(error) = error {
            let trap_result = self.handle_error(error)?;
            self.emit_trap_mem_instr_event(
                instruction,
                a,
                b,
                c,
                &mem_access_record,
                trap_result,
                op_a_0,
            );
        } else {
            self.emit_mem_instr_event(instruction, a, b, c, &mem_access_record, op_a_0);
        }

        self.emit_events(
            self.core.clk(),
            self.core.next_pc(),
            is_trap,
            false,
            instruction,
            &mem_access_record,
            0,
        );

        Ok(())
    }

    /// Execute a store instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the store instruction.
    fn execute_store(
        &mut self,
        instruction: &Instruction,
        untrusted_instruction_record: Option<&MemoryReadRecord>,
        pc: u64,
    ) -> Result<(), ExecutionError> {
        let StoreResult { mut a, b, c, rs1, rs2, addr, rs1_record, rs2_record, mw_record, error } =
            self.core.execute_store(instruction)?;

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Read(rs1_record)),
            b: Some(MemoryRecordEnum::Read(rs2_record)),
            c: None,
            memory: Some(MemoryRecordEnum::Write(mw_record)),
            untrusted_instruction: untrusted_instruction_record
                .map(|&record| (record.into(), (record.value >> (pc % 8 * 8)) as u32)),
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        if error.is_none() {
            self.local_memory_access.insert_record(addr & !0b111, mw_record);
        }
        self.local_memory_access.insert_record(rs1 as u64, rs1_record);
        self.local_memory_access.insert_record(rs2 as u64, rs2_record);
        if let Some(untrusted_instruction_record) = untrusted_instruction_record {
            self.local_memory_access.insert_record(pc & !0b111, *untrusted_instruction_record);
            self.local_page_prot_access.insert_record(
                pc / PAGE_SIZE as u64,
                untrusted_instruction_record.prev_page_prot_record.unwrap(),
                self.core.clk(),
                untrusted_instruction_record.prev_page_prot_record.unwrap().page_prot,
            );
        }

        self.local_page_prot_access.insert_record(
            addr / PAGE_SIZE as u64,
            mw_record.prev_page_prot_record.unwrap(),
            self.core.clk() + MemoryAccessPosition::Memory as u64,
            mw_record.prev_page_prot_record.unwrap().page_prot,
        );

        let is_trap = error.is_some();

        if let Some(error) = error {
            let trap_result = self.handle_error(error)?;
            self.emit_trap_mem_instr_event(
                instruction,
                a,
                b,
                c,
                &mem_access_record,
                trap_result,
                op_a_0,
            );
        } else {
            self.emit_mem_instr_event(instruction, a, b, c, &mem_access_record, op_a_0);
        }

        self.emit_events(
            self.core.clk(),
            self.core.next_pc(),
            is_trap,
            false,
            instruction,
            &mem_access_record,
            0,
        );

        Ok(())
    }
}

impl<M: ExecutionMode> TracingVM<'_, M> {
    fn postprocess(&mut self)
    where
        for<'b> TracingVM<'b, M>: StepInstruction,
    {
        // Produce software records for any APC blocks whose candidate aborted under the skip gate
        // (must run before the `contains_cpu` check below, since it can be the only source of CPU
        // events in an all-APC shard).
        self.flush_aborted_blocks();

        if self.record.last_timestamp == 0 {
            self.record.last_timestamp = self.core.clk();
        }

        self.record.program = self.core.program.clone();
        self.record.public_values.is_untrusted_programs_enabled = M::PAGE_PROTECTION_ENABLED as u32;

        if self.record.contains_cpu() {
            self.record.public_values.pc_start = self.record.pc_start.unwrap();
            self.record.public_values.next_pc = self.record.next_pc;
            self.record.public_values.exit_code = self.record.exit_code;
            self.record.public_values.last_timestamp = self.record.last_timestamp;
            self.record.public_values.initial_timestamp = self.record.initial_timestamp;
        }

        for (_, event) in self.local_memory_access.inner.drain() {
            self.record.cpu_local_memory_access.push(event);
        }

        if M::PAGE_PROTECTION_ENABLED {
            for (_, event) in self.local_page_prot_access.inner.drain() {
                self.record.cpu_local_page_prot_access.push(event);
            }

            let decoded_events =
                std::mem::replace(&mut self.decoded_instruction_events, HashMap::new());
            self.record.instruction_decode_events.extend(decoded_events.into_values());
        }
    }

    fn register_refresh(&mut self) {
        for (addr, record) in self.core.register_refresh().into_iter().enumerate() {
            self.local_memory_access.insert_record(addr as u64, record);

            self.record.bump_memory_events.push((
                MemoryRecordEnum::Read(record),
                addr as u64,
                true,
            ));
        }
    }

    /// Get the current registers (immutable).
    #[must_use]
    pub fn registers(&self) -> &[MemoryRecord; 32] {
        self.core.registers()
    }

    /// This object is used to read and write memory in a precompile.
    #[must_use]
    pub fn registers_mut(&mut self) -> &mut [MemoryRecord; 32] {
        self.core.registers_mut()
    }
}

impl<'a, M: ExecutionMode> TracingVM<'a, M> {
    /// Create a new full-tracing VM from a minimal trace.
    pub fn new<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        opts: SP1CoreOpts,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        record: &'a mut ExecutionRecord,
    ) -> Self {
        record.initial_timestamp = trace.clk_start();

        // Record-in-chip is the default (no env gate): whenever the program has any APCs, skip
        // per-opcode emission inside their blocks and capture each invocation instead. The APC
        // chip regenerates its trace by re-executing the captured invocations.
        let has_apcs = !program.apcs.apc_by_index.is_empty();

        // Build the static APC pc map, indexed by `pc_idx = (pc - pc_base) / 4`, holding the APC
        // id whose static cycle range contains that PC (`None` outside any range). APCs are basic
        // blocks, so a single contiguous fill per APC is correct. Left empty when there are no APCs
        // (and on the replay VM): a non-empty map is exactly the "this VM skips + captures" signal
        // (see [`Self::capturing`]), and it avoids allocating a program-length all-`None` vec.
        let mut apc_id_by_pc_idx =
            if has_apcs { vec![None; program.instructions.len()] } else { Vec::new() };
        if has_apcs {
            for (apc_id, apc) in program.apcs.apc_by_index.iter().enumerate() {
                let start = apc.start_pc_idx();
                let end = (start + apc.num_cycles()).min(apc_id_by_pc_idx.len());
                if start < apc_id_by_pc_idx.len() {
                    for slot in &mut apc_id_by_pc_idx[start..end] {
                        *slot = Some(apc_id);
                    }
                }
            }
        }

        // Retain the shard's full read oracle (independent cursor — does not disturb CoreVM's) so
        // per-APC blocks can be sliced out for capture / replayed on abort.
        let shard_reads: Arc<[sp1_jit::MemValue]> =
            if has_apcs { trace.mem_reads().collect() } else { Arc::from([]) };

        // Bump-resilient APC: under APC capture, let register (rr/rw) and RAM (mr/mw) accesses that
        // cross a 2^24 timestamp epoch stay APCs instead of aborting to software. Register
        // crossings are routed to the shared `MemoryBump` chip via `pending_register_bumps`; RAM
        // crossings are represented natively by `compare_low` (no bump needed). State/pc bumps and
        // `register_refresh` still abort.
        let mut core = CoreVM::new(trace, program, opts, proof_nonce);
        core.apc_register_bump_tolerant = has_apcs;
        core.apc_ram_bump_tolerant = has_apcs;

        Self {
            core,
            record,
            local_memory_access: LocalMemoryAccess::default(),
            local_page_prot_access: LocalPageProtAccess::default(),
            precompile_local_memory_access: None,
            precompile_local_page_prot_access: None,
            decoded_instruction_events: HashMap::new(),
            shard_reads,
            apc_pre_states: HashMap::new(),
            apc_id_by_pc_idx: Arc::new(apc_id_by_pc_idx),
            current_skip: None,
            pending_register_bumps: Vec::new(),
            _mode: PhantomData,
        }
    }

    /// Lightweight constructor for record-in-chip block replay ([`Self::reexecute_apc_block_into`]).
    /// Uses an untracked [`CoreVM`] (no candidate work), an empty APC pc-map (every lookup →
    /// `None`, so the gate stays inert), and no read-oracle copy. Capture is off. Candidate
    /// detection never fires during replay, so this is correct and cheap.
    fn new_replay<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        opts: SP1CoreOpts,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        record: &'a mut ExecutionRecord,
    ) -> Self {
        record.initial_timestamp = trace.clk_start();
        Self {
            core: CoreVM::new_untracked(trace, program, opts, proof_nonce),
            record,
            local_memory_access: LocalMemoryAccess::default(),
            local_page_prot_access: LocalPageProtAccess::default(),
            precompile_local_memory_access: None,
            precompile_local_page_prot_access: None,
            decoded_instruction_events: HashMap::new(),
            shard_reads: Arc::from([]),
            apc_pre_states: HashMap::new(),
            apc_id_by_pc_idx: Arc::new(Vec::new()),
            current_skip: None,
            pending_register_bumps: Vec::new(),
            _mode: PhantomData,
        }
    }

    /// Whether this VM is doing record-in-chip APC capture: skipping per-opcode emission inside
    /// APC blocks and capturing each as an [`ApcInvocation`]. True iff the program has APCs and this
    /// is not a replay VM — exactly when the APC pc-map is non-empty (it is left empty for both no-
    /// APC programs and the replay VM). Skip and capture must agree, so deriving both from the same
    /// map makes the invalid "skip without capture" state unrepresentable.
    #[inline]
    fn capturing(&self) -> bool {
        !self.apc_id_by_pc_idx.is_empty()
    }

    /// Record-in-chip: run at the start of a cycle, BEFORE `fetch`. Computes the APC id whose
    /// static range contains the current PC, resolves any in-progress skip invocation that just
    /// left its range (flushing its skipped prefix as software), captures the entry pre-state for
    /// any APC starting at this PC, and begins this block's skip invocation. Returns the current
    /// `apc_id` (`None` outside any APC range) for the caller to pass to [`Self::set_skip_gate`].
    fn begin_cycle(&mut self) -> Option<usize>
    where
        for<'b> TracingVM<'b, M>: StepInstruction,
    {
        let pc_idx = self.core.pc().wrapping_sub(self.core.program.pc_base) as usize / 4;
        let apc_id = self.apc_id_by_pc_idx.get(pc_idx).copied().flatten();

        if self.capturing() {
            // Resolve the in-progress skip invocation if execution has just left its APC's static
            // range without a successful `ApcCall` — i.e. the candidate aborted (bump /
            // optimistic-constraint failure) or branched out. Its skipped prefix must be emitted
            // as software. Doing this here, per-invocation, is what makes loops correct: a later
            // invocation of the same `apc_id` can no longer discard this aborted one's flush.
            if let Some(cs) = self.current_skip {
                if apc_id != Some(cs.apc_id) {
                    self.current_skip = None;
                    self.flush_invocation(cs);
                }
            }

            self.record.mem_reads_remaining = self.core.mem_reads.len();
            // Single map lookup on the per-cycle hot path: `None` for the vast majority of cycles.
            if let Some(apc_ids) =
                self.core.program.apcs.apc_indices_by_start_idx.get(&pc_idx).cloned()
            {
                // A still-unresolved invocation at a fresh APC start means its candidate aborted
                // and execution looped straight back into an APC range without ever leaving it, so
                // the range-exit flush above never fired. Flush it now, *before* its captured
                // pre-state is overwritten below: while skipping, `cpu_event_count` (the pre-state
                // key) does not advance, so this start would otherwise clobber the entry.
                if let Some(prev) = self.current_skip.take() {
                    self.flush_invocation(prev);
                }
                let entry = CoreEntryState {
                    registers: *self.core.registers(),
                    pc: self.core.pc(),
                    clk: self.core.clk(),
                    global_clk: self.core.global_clk(),
                    mem_reads_remaining: self.record.mem_reads_remaining,
                };
                let key_clk = self.record.cpu_event_count;
                for &id in &apc_ids {
                    self.apc_pre_states.insert((id, key_clk), entry.clone());
                }
                // `apc_id` (static-range membership at this start) is the APC starting here and is
                // one of `apc_ids`; track its invocation so only it is skipped / flushed.
                if let (true, Some(id)) = (self.capturing(), apc_id) {
                    self.current_skip = Some(CurrentSkip { apc_id: id, key_clk, count: 0 });
                }
            }
        }

        apc_id
    }

    /// Record-in-chip: set the per-cycle skip gate, run BEFORE the opcode dispatch. Suppresses
    /// per-opcode event emission while an APC block's invocation is in progress in this shard.
    /// `insert_record` (local memory / page prot) is kept running regardless, so the local-memory
    /// and page-prot buses stay complete.
    fn set_skip_gate(&mut self, apc_id: Option<usize>) {
        let gate_active =
            self.capturing() && self.current_skip.is_some_and(|cs| apc_id == Some(cs.apc_id));
        self.record.skip_writes = gate_active;
        if gate_active {
            self.current_skip.as_mut().unwrap().count += 1;
        }
    }

    /// Record-in-chip: run AFTER `advance`. Updates the read-oracle cursor, captures an
    /// [`ApcInvocation`] for each successful call, and discards the in-progress skip invocation if
    /// it succeeded (the APC chip regenerates its rows).
    fn end_cycle_capture(&mut self, calls: &[ApcCall<ExecutionRecordSnapshot>]) {
        if !self.capturing() {
            return;
        }
        if !calls.is_empty() {
            self.capture_invocations(calls);
            // If the in-progress skip invocation just succeeded (its `apc_id` is among the
            // extracted calls), discard its skip accounting: the APC chip regenerates its rows via
            // re-execution, so no software rollback is needed. (`capture_invocations` already
            // removed its `apc_pre_states` entry.)
            if let Some(cs) = self.current_skip {
                if calls.iter().any(|c| c.apc_id == cs.apc_id) {
                    self.current_skip = None;
                    // Bump-resilient APC: the skip block completed as an APC — commit its collected
                    // register epoch-crossing bumps to the shared `MemoryBump` chip (the APC's
                    // re-anchored register read, `prev_low=0`, needs the balancing shadow read).
                    if !self.pending_register_bumps.is_empty() {
                        let mut pending = std::mem::take(&mut self.pending_register_bumps);
                        self.record.bump_memory_events.append(&mut pending);
                    }
                }
            }
        }
    }

    /// Build an [`ApcInvocation`] for each successful APC call by pairing the call's entry
    /// pre-state (looked up by `(apc_id, from.cpu_event_count)`) with the block's read-oracle slice
    /// (derived from the from/to `mem_reads_remaining`), and store it on the record.
    fn capture_invocations(&mut self, calls: &[ApcCall<ExecutionRecordSnapshot>]) {
        let total = self.shard_reads.len();
        for call in calls {
            let key = (call.apc_id, call.from.cpu_event_count);
            let Some(entry) = self.apc_pre_states.remove(&key) else {
                debug_assert!(false, "missing captured pre-state for apc {}", call.apc_id);
                continue;
            };
            let entry_offset = total - call.from.mem_reads_remaining;
            let exit_offset = total - call.to.mem_reads_remaining;
            let num_instructions = self.core.program.apcs.apc_by_index[call.apc_id].num_cycles();
            // Zero-copy: share the shard read-oracle `Arc` (refcount bump) and store only this
            // block's `[entry_offset, exit_offset)` range, instead of copying the slice.
            self.record.apc_invocations.push(crate::autoprecompiles::ApcInvocation {
                apc_id: call.apc_id,
                pre_registers: entry.registers,
                pc_start: entry.pc,
                clk_start: entry.clk,
                global_clk_start: entry.global_clk,
                reads: self.shard_reads.clone(),
                read_offset: entry_offset,
                read_len: exit_offset - entry_offset,
                num_instructions,
            });
        }
    }

    /// Re-execute the skipped prefix of one aborted/segmented APC invocation as software — the
    /// "rollback" half of the skip optimization. Replays exactly `cs.count` instructions (the
    /// number skipped in this shard) from the captured entry pre-state and appends the events to
    /// the main record. Memory-local accesses are already in the main map (the gate keeps
    /// `insert_record` running), so the replay covers only per-opcode / bump rows.
    fn flush_invocation(&mut self, cs: CurrentSkip)
    where
        for<'b> TracingVM<'b, M>: StepInstruction,
    {
        // Bump-resilient APC: this skip block aborted — discard its collected register bumps; the
        // flush replay below re-emits them as part of the software block (avoids double-counting).
        self.pending_register_bumps.clear();
        if cs.count == 0 {
            return;
        }
        let Some(entry) = self.apc_pre_states.remove(&(cs.apc_id, cs.key_clk)) else {
            debug_assert!(false, "no captured pre-state for aborted apc {}", cs.apc_id);
            return;
        };
        let program = self.core.program.clone();
        let opts = self.core.opts.clone();
        let nonce = self.core.proof_nonce;
        let entry_offset = self.shard_reads.len() - entry.mem_reads_remaining;
        // Zero-copy: share the shard read-oracle `Arc` and expose only THIS block's reads
        // `[entry_offset, current cursor)`. Replay steps exactly `cs.count` instructions.
        let read_end = self.shard_reads.len() - self.core.mem_reads.len();
        let trace = sp1_jit::ReplayTrace::new(
            self.shard_reads.clone(),
            entry_offset,
            read_end - entry_offset,
            entry.registers.map(|r| r.value),
            entry.pc,
            entry.clk,
            // Generous clk_end so nothing trace-ends mid-block; the loop bounds execution.
            entry.clk + (cs.count as u64 + 16) * 8,
        );
        Self::replay_block_into(
            &trace,
            &entry.registers,
            entry.global_clk,
            cs.count,
            program,
            opts,
            nonce,
            self.record,
        )
        .expect("flush_invocation: replay_block_into failed");
    }

    /// Flush the skip invocation still in progress at shard end (a segmentation abort — its block
    /// straddles the shard boundary). Its in-shard prefix is emitted as software; the continuation
    /// is handled by the next shard. (Successful, range-exit-aborted, and loop-aborted invocations
    /// were already resolved during execution.)
    fn flush_aborted_blocks(&mut self)
    where
        for<'b> TracingVM<'b, M>: StepInstruction,
    {
        if let Some(cs) = self.current_skip.take() {
            self.flush_invocation(cs);
        }
    }

    /// Re-execute a single APC block from its minimal [`ApcInvocation`] record, appending the
    /// block's per-opcode events directly into `target`. This is the record-in-chip tracegen
    /// primitive: instead of carving the block's events out of a full software trace, we
    /// regenerate them by replaying the block from the captured pre-state. `target`'s
    /// `initial_timestamp` is preserved.
    pub fn reexecute_apc_block_into(
        invocation: &crate::autoprecompiles::ApcInvocation,
        program: Arc<Program>,
        opts: SP1CoreOpts,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        target: &mut ExecutionRecord,
    ) -> Result<(), ExecutionError>
    where
        for<'b> TracingVM<'b, M>: StepInstruction,
    {
        // Zero-copy: replay from the invocation's shared read-oracle `Arc` + range, exactly like
        // the skip-flush path. Building an owned `TraceChunk` here would clone the reads a second
        // time (the first copy was already removed from capture).
        let trace = sp1_jit::ReplayTrace::new(
            invocation.reads.clone(),
            invocation.read_offset,
            invocation.read_len,
            invocation.pre_registers.map(|r| r.value),
            invocation.pc_start,
            invocation.clk_start,
            invocation.clk_start + (invocation.num_instructions as u64 + 16) * 8,
        );
        Self::replay_block_into(
            &trace,
            &invocation.pre_registers,
            invocation.global_clk_start,
            invocation.num_instructions,
            program,
            opts,
            proof_nonce,
            target,
        )
    }

    /// Replay `num_instructions` from any minimal trace directly into `target`. Shared by
    /// [`Self::reexecute_apc_block_into`] and the skip-flush path — both build a zero-copy
    /// [`sp1_jit::ReplayTrace`] sharing the shard read-oracle `Arc`. The replay VM forces the
    /// skip gate inert and capture off, so candidate detection during replay is harmless.
    /// `target.initial_timestamp` is preserved.
    #[allow(clippy::too_many_arguments)]
    fn replay_block_into<T: MinimalTrace>(
        trace: &T,
        pre_registers: &[MemoryRecord; 32],
        global_clk_start: u64,
        num_instructions: usize,
        program: Arc<Program>,
        opts: SP1CoreOpts,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        target: &mut ExecutionRecord,
    ) -> Result<(), ExecutionError>
    where
        for<'b> TracingVM<'b, M>: StepInstruction,
    {
        let saved_initial = target.initial_timestamp;
        {
            let mut vm = TracingVM::<M>::new_replay(trace, program, opts, proof_nonce, target);
            // Restore register prev-access timestamps (the trace carries values only).
            *vm.core.registers_mut() = *pre_registers;
            vm.core.set_global_clk(global_clk_start);
            for _ in 0..num_instructions {
                vm.step_instruction()?;
            }
        }
        target.initial_timestamp = saved_initial;
        Ok(())
    }

    /// Get the public values from the record.
    #[must_use]
    pub fn public_values(&self) -> &PublicValues<u32, u64, u64, u32> {
        &self.record.public_values
    }

    /// Handle a trap.
    pub fn handle_error(&mut self, e: TrapError) -> Result<TrapResult, ExecutionError> {
        let trap_result = self.core.handle_error(e)?;

        self.local_memory_access.insert_record(trap_result.context, trap_result.handler_record);
        self.local_memory_access.insert_record(trap_result.context + 8, trap_result.code_record);
        self.local_memory_access.insert_record(trap_result.context + 16, trap_result.pc_record);

        Ok(trap_result)
    }

    /// Execute an ALU instruction and emit the events.
    fn execute_alu(
        &mut self,
        instruction: &Instruction,
        untrusted_instruction_record: Option<&MemoryReadRecord>,
        pc: u64,
    ) {
        let AluResult { rd, rw_record, mut a, b, c, rs1, rs2 } = self.core.execute_alu(instruction);

        if let MaybeImmediate::Register(rs2, rs2_record) = rs2 {
            self.local_memory_access.insert_record(rs2 as u64, rs2_record);
        }

        if let MaybeImmediate::Register(rs1, rs1_record) = rs1 {
            self.local_memory_access.insert_record(rs1 as u64, rs1_record);
        }

        self.local_memory_access.insert_record(rd as u64, rw_record);
        if let Some(untrusted_instruction_record) = untrusted_instruction_record {
            self.local_memory_access.insert_record(pc & !0b111, *untrusted_instruction_record);
            self.local_page_prot_access.insert_record(
                pc / PAGE_SIZE as u64,
                untrusted_instruction_record.prev_page_prot_record.unwrap(),
                self.core.clk(),
                untrusted_instruction_record.prev_page_prot_record.unwrap().page_prot,
            );
        }

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(rw_record)),
            b: rs1.record().map(|r| MemoryRecordEnum::Read(*r)),
            c: rs2.record().map(|r| MemoryRecordEnum::Read(*r)),
            memory: None,
            untrusted_instruction: untrusted_instruction_record
                .map(|&record| (record.into(), (record.value >> (pc % 8 * 8)) as u32)),
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.emit_events(
            self.core.clk(),
            self.core.next_pc(),
            false,
            false,
            instruction,
            &mem_access_record,
            0,
        );
        self.emit_alu_event(instruction, a, b, c, &mem_access_record, op_a_0);
    }

    /// Execute a jump instruction and emit the events.
    fn execute_jump(
        &mut self,
        instruction: &Instruction,
        untrusted_instruction_record: Option<&MemoryReadRecord>,
        pc: u64,
    ) {
        let JumpResult { mut a, b, c, rd, rd_record, rs1 } = self.core.execute_jump(instruction);

        if let MaybeImmediate::Register(rs1, rs1_record) = rs1 {
            self.local_memory_access.insert_record(rs1 as u64, rs1_record);
        }

        self.local_memory_access.insert_record(rd as u64, rd_record);
        if let Some(untrusted_instruction_record) = untrusted_instruction_record {
            self.local_memory_access.insert_record(pc & !0b111, *untrusted_instruction_record);
            self.local_page_prot_access.insert_record(
                pc / PAGE_SIZE as u64,
                untrusted_instruction_record.prev_page_prot_record.unwrap(),
                self.core.clk(),
                untrusted_instruction_record.prev_page_prot_record.unwrap().page_prot,
            );
        }

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(rd_record)),
            b: rs1.record().map(|r| MemoryRecordEnum::Read(*r)),
            c: None,
            memory: None,
            untrusted_instruction: untrusted_instruction_record
                .map(|&record| (record.into(), (record.value >> (pc % 8 * 8)) as u32)),
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.emit_events(
            self.core.clk(),
            self.core.next_pc(),
            false,
            false,
            instruction,
            &mem_access_record,
            0,
        );
        match instruction.opcode {
            Opcode::JAL => self.emit_jal_event(
                instruction,
                a,
                b,
                c,
                &mem_access_record,
                op_a_0,
                self.core.next_pc(),
            ),
            Opcode::JALR => self.emit_jalr_event(
                instruction,
                a,
                b,
                c,
                &mem_access_record,
                op_a_0,
                self.core.next_pc(),
            ),
            _ => unreachable!("Invalid opcode for `execute_jump`: {:?}", instruction.opcode),
        }
    }

    /// Execute a branch instruction and emit the events.
    fn execute_branch(
        &mut self,
        instruction: &Instruction,
        untrusted_instruction_record: Option<&MemoryReadRecord>,
        pc: u64,
    ) {
        let BranchResult { mut a, rs1, a_record, b, rs2, b_record, c } =
            self.core.execute_branch(instruction);

        self.local_memory_access.insert_record(rs2 as u64, b_record);
        self.local_memory_access.insert_record(rs1 as u64, a_record);
        if let Some(untrusted_instruction_record) = untrusted_instruction_record {
            self.local_memory_access.insert_record(pc & !0b111, *untrusted_instruction_record);
            self.local_page_prot_access.insert_record(
                pc / PAGE_SIZE as u64,
                untrusted_instruction_record.prev_page_prot_record.unwrap(),
                self.core.clk(),
                untrusted_instruction_record.prev_page_prot_record.unwrap().page_prot,
            );
        }

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Read(a_record)),
            b: Some(MemoryRecordEnum::Read(b_record)),
            c: None,
            memory: None,
            untrusted_instruction: untrusted_instruction_record
                .map(|&record| (record.into(), (record.value >> (pc % 8 * 8)) as u32)),
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.emit_events(
            self.core.clk(),
            self.core.next_pc(),
            false,
            false,
            instruction,
            &mem_access_record,
            0,
        );
        self.emit_branch_event(
            instruction,
            a,
            b,
            c,
            &mem_access_record,
            op_a_0,
            self.core.next_pc(),
        );
    }

    /// Execute a U-type instruction and emit the events.   
    fn execute_utype(
        &mut self,
        instruction: &Instruction,
        untrusted_instruction_record: Option<&MemoryReadRecord>,
        pc: u64,
    ) {
        let UTypeResult { mut a, b, c, rd, rw_record } = self.core.execute_utype(instruction);

        self.local_memory_access.insert_record(rd as u64, rw_record);
        if let Some(untrusted_instruction_record) = untrusted_instruction_record {
            self.local_memory_access.insert_record(pc & !0b111, *untrusted_instruction_record);
            self.local_page_prot_access.insert_record(
                pc / PAGE_SIZE as u64,
                untrusted_instruction_record.prev_page_prot_record.unwrap(),
                self.core.clk(),
                untrusted_instruction_record.prev_page_prot_record.unwrap().page_prot,
            );
        }

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(rw_record)),
            b: None,
            c: None,
            memory: None,
            untrusted_instruction: untrusted_instruction_record
                .map(|&record| (record.into(), (record.value >> (pc % 8 * 8)) as u32)),
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.emit_events(
            self.core.clk(),
            self.core.next_pc(),
            false,
            false,
            instruction,
            &mem_access_record,
            0,
        );
        self.emit_utype_event(instruction, a, b, c, &mem_access_record, op_a_0);
    }

    /// Execute an ecall instruction and emit the events.
    fn execute_ecall(
        &mut self,
        instruction: &Instruction,
        untrusted_instruction_record: Option<&MemoryReadRecord>,
        pc: u64,
    ) -> Result<(), ExecutionError> {
        let code = self.core.read_code();
        let is_sigreturn = code == SyscallCode::SIG_RETURN;

        // If the syscall is not retained, we need to track the local memory access separately.
        //
        // Note that the `precompile_local_memory_access` is set to `None` in the
        // `postprocess_precompile` method.
        if !self.core().is_retained_syscall(code) && code.should_send() == 1 {
            self.precompile_local_memory_access = Some(LocalMemoryAccess::default());
            if M::PAGE_PROTECTION_ENABLED {
                self.precompile_local_page_prot_access = Some(LocalPageProtAccess::default());
            } else {
                self.precompile_local_page_prot_access = None;
            }
        } else {
            self.precompile_local_page_prot_access = None;
            self.precompile_local_memory_access = None;
        }

        if is_sigreturn {
            let c_record_peek = self.core().rr_peek(Register::X11, MemoryAccessPosition::C);
            let b_record_peek = self.core().rr_peek(Register::X10, MemoryAccessPosition::B);
            let a_record_peek = self.core().rr_peek(Register::X5, MemoryAccessPosition::A);
            self.local_memory_access.insert_record(Register::X11 as u64, c_record_peek);
            self.local_memory_access.insert_record(Register::X10 as u64, b_record_peek);
            self.local_memory_access.insert_record(Register::X5 as u64, a_record_peek);
        }

        // Actually execute the ecall.
        let EcallResult { a: _, a_record, b, b_record, c, c_record, error, sig_return_pc_record } =
            CoreVM::<'a, M, ExecutionRecordSnapshot>::execute_ecall(
                &mut PrecompileMemory::new(self),
                instruction,
                code,
            )?;

        if let Some(record) = sig_return_pc_record {
            self.local_memory_access.insert_record(b, record);
        }

        if !is_sigreturn {
            self.local_memory_access.insert_record(Register::X11 as u64, c_record);
            self.local_memory_access.insert_record(Register::X10 as u64, b_record);
            self.local_memory_access.insert_record(Register::X5 as u64, a_record);
        }

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(a_record)),
            b: Some(MemoryRecordEnum::Read(b_record)),
            c: Some(MemoryRecordEnum::Read(c_record)),
            memory: None,
            untrusted_instruction: untrusted_instruction_record
                .map(|&record| (record.into(), (record.value >> (pc % 8 * 8)) as u32)),
        };

        let is_trap = error.is_some();
        let trap_result =
            if let Some(ref err) = error { Some(self.handle_error(*err)?) } else { None };

        self.emit_events(
            self.core.clk(),
            self.core.next_pc(),
            is_trap,
            is_sigreturn,
            instruction,
            &mem_access_record,
            self.core.exit_code(),
        );

        self.emit_syscall_event(
            self.core.clk(),
            code,
            b,
            c,
            &mem_access_record,
            self.core.next_pc(),
            self.core.exit_code(),
            instruction,
            sig_return_pc_record,
            trap_result,
            error,
        );

        Ok(())
    }
}

impl<M: ExecutionMode> TracingVM<'_, M> {
    /// Emit events for a trap.
    fn emit_trap_events(&mut self, clk: u64, next_pc: u64) {
        self.record.pc_start.get_or_insert(self.core.pc());
        self.record.next_pc = next_pc;
        self.record.cpu_event_count += 1;

        let increment = self.core.next_clk() - clk;

        let bump1 = clk % (1 << 24) + increment >= (1 << 24);
        if bump1 {
            self.record.bump_state_events.push((clk, increment, false, next_pc));
        }
    }

    /// Emit events for this cycle.
    #[allow(clippy::too_many_arguments)]
    fn emit_events(
        &mut self,
        clk: u64,
        next_pc: u64,
        is_trap: bool,
        is_sig_return: bool,
        instruction: &Instruction,
        record: &MemoryAccessRecord,
        exit_code: u32,
    ) {
        // `pc_start`/`next_pc` are shard-level state-continuity values committed to the public
        // values (State bus). They must be maintained even inside APC ranges where per-cycle
        // events are skipped: otherwise, when the shard's first cycle falls in a skipped APC block,
        // `pc_start` (set via `get_or_insert`) would latch the first non-skipped pc instead of the
        // true shard start, producing a State-bus cumulative-sum mismatch at the initial boundary.
        self.record.pc_start.get_or_insert(self.core.pc());
        self.record.next_pc = next_pc;
        if self.record.skip_writes {
            // Bump-resilient APC (register half): inside a skipped APC range that is a tracked
            // in-progress candidate, collect any register epoch-crossing bumps into the pending
            // buffer (committed on APC success, discarded on flush). Gated on `current_skip` so a
            // mid-block segmentation resume (skipped, but with no tracked candidate to
            // resolve/commit it) never leaks bumps. State/pc bumps and RAM are NOT collected here —
            // those still abort the candidate.
            if self.capturing() && self.current_skip.is_some() {
                Self::collect_register_bumps(&mut self.pending_register_bumps, instruction, record);
            }
            return;
        }
        self.record.exit_code = exit_code;
        self.record.cpu_event_count += 1;

        let increment = self.core.next_clk() - clk;

        let bump1 = clk % (1 << 24) + increment >= (1 << 24);
        let bump2 = !instruction.is_with_correct_next_pc()
            && !is_trap
            && !is_sig_return
            && next_pc == self.core.pc().wrapping_add(4)
            && (next_pc >> 16) != (self.core.pc() >> 16);

        if bump1 || bump2 {
            self.record.bump_state_events.push((clk, increment, bump2, next_pc));
        }

        if let Some(x) = record.a {
            if x.current_record().timestamp >> 24 != x.previous_record().timestamp >> 24 {
                self.record.bump_memory_events.push((x, instruction.op_a as u64, false));
            }
        }
        if let Some(x) = record.b {
            if x.current_record().timestamp >> 24 != x.previous_record().timestamp >> 24 {
                self.record.bump_memory_events.push((x, instruction.op_b, false));
            }
        }
        if let Some(x) = record.c {
            if x.current_record().timestamp >> 24 != x.previous_record().timestamp >> 24 {
                self.record.bump_memory_events.push((x, instruction.op_c, false));
            }
        }

        if let Some((_record, instruction_value)) = record.untrusted_instruction {
            let encoded_instruction = instruction_value;

            self.emit_instruction_fetch_event(instruction, encoded_instruction, record);

            self.decoded_instruction_events
                .entry(encoded_instruction)
                .and_modify(|e| e.multiplicity += 1)
                .or_insert_with(|| InstructionDecodeEvent {
                    instruction: *instruction,
                    encoded_instruction,
                    multiplicity: 1,
                });
        }
    }

    /// Bump-resilient APC helper: collect a register-refresh bump event for each operand (a/b/c)
    /// whose access crosses a 2^24 timestamp epoch. Same predicate as the direct emission in
    /// [`Self::emit_events`], but appends into `out` (the pending buffer) instead of the record.
    fn collect_register_bumps(
        out: &mut Vec<(MemoryRecordEnum, u64, bool)>,
        instruction: &Instruction,
        record: &MemoryAccessRecord,
    ) {
        if let Some(x) = record.a {
            if x.current_record().timestamp >> 24 != x.previous_record().timestamp >> 24 {
                out.push((x, instruction.op_a as u64, false));
            }
        }
        if let Some(x) = record.b {
            if x.current_record().timestamp >> 24 != x.previous_record().timestamp >> 24 {
                out.push((x, instruction.op_b, false));
            }
        }
        if let Some(x) = record.c {
            if x.current_record().timestamp >> 24 != x.previous_record().timestamp >> 24 {
                out.push((x, instruction.op_c, false));
            }
        }
    }

    // Emit an event for a trap due to an untrusted instruction not having permission.
    fn emit_trap_exec_event(&mut self, trap_result: TrapResult, page_prot_record: PageProtRecord) {
        let event = TrapExecEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            trap_result,
            page_prot_record,
        };
        self.record.trap_exec_events.push(event);
    }

    /// Emit a instruction fetch event.
    #[allow(clippy::too_many_arguments)]
    fn emit_instruction_fetch_event(
        &mut self,
        instruction: &Instruction,
        encoded_instruction: u32,
        record: &MemoryAccessRecord,
    ) {
        let event = InstructionFetchEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            instruction: *instruction,
            encoded_instruction,
        };
        self.record.instruction_fetch_events.push((event, *record));
    }

    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn emit_trap_mem_instr_event(
        &mut self,
        instruction: &Instruction,
        a: u64,
        b: u64,
        c: u64,
        record: &MemoryAccessRecord,
        trap_result: TrapResult,
        op_a_0: bool,
    ) {
        let opcode = instruction.opcode;
        let event = TrapMemInstrEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            opcode,
            a,
            b,
            c,
            op_a_0,
            page_prot_access: record.memory.unwrap().previous_page_prot_record().unwrap(),
            trap_result,
        };
        let record = ITypeRecord::new(record, instruction);
        self.record.trap_load_store_events.push((event, record));
    }

    /// Emit a memory instruction event.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn emit_mem_instr_event(
        &mut self,
        instruction: &Instruction,
        a: u64,
        b: u64,
        c: u64,
        record: &MemoryAccessRecord,
        op_a_0: bool,
    ) {
        if self.record.skip_writes {
            return;
        }
        let opcode = instruction.opcode;
        let event = MemInstrEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            opcode,
            a,
            b,
            c,
            op_a_0,
            // SAFETY: We explicity populate the memory of the record on the following callsites:
            // - `execute_load`
            // - `execute_store`
            mem_access: unsafe { record.memory.unwrap_unchecked() },
        };

        let record = ITypeRecord::new(record, instruction);
        if matches!(
            opcode,
            Opcode::LB
                | Opcode::LBU
                | Opcode::LH
                | Opcode::LHU
                | Opcode::LW
                | Opcode::LWU
                | Opcode::LD
        ) && op_a_0
        {
            self.record.memory_load_x0_events.push((event, record));
        } else if matches!(opcode, Opcode::LB | Opcode::LBU) {
            self.record.memory_load_byte_events.push((event, record));
        } else if matches!(opcode, Opcode::LH | Opcode::LHU) {
            self.record.memory_load_half_events.push((event, record));
        } else if matches!(opcode, Opcode::LW | Opcode::LWU) {
            self.record.memory_load_word_events.push((event, record));
        } else if opcode == Opcode::LD {
            self.record.memory_load_double_events.push((event, record));
        } else if opcode == Opcode::SB {
            self.record.memory_store_byte_events.push((event, record));
        } else if opcode == Opcode::SH {
            self.record.memory_store_half_events.push((event, record));
        } else if opcode == Opcode::SW {
            self.record.memory_store_word_events.push((event, record));
        } else if opcode == Opcode::SD {
            self.record.memory_store_double_events.push((event, record));
        }
    }

    /// Emit an ALU event.
    fn emit_alu_event(
        &mut self,
        instruction: &Instruction,
        a: u64,
        b: u64,
        c: u64,
        record: &MemoryAccessRecord,
        op_a_0: bool,
    ) {
        if self.record.skip_writes {
            return;
        }
        let opcode = instruction.opcode;
        let event = AluEvent { clk: self.core.clk(), pc: self.core.pc(), opcode, a, b, c, op_a_0 };

        if op_a_0 {
            let record = ALUTypeRecord::new(record, instruction);
            self.record.alu_x0_events.push((event, record));
            return;
        }

        match opcode {
            Opcode::ADD => {
                let record = RTypeRecord::new(record, instruction);
                self.record.add_events.push((event, record));
            }
            Opcode::ADDW => {
                let record = ALUTypeRecord::new(record, instruction);
                self.record.addw_events.push((event, record));
            }
            Opcode::ADDI => {
                let record = ITypeRecord::new(record, instruction);
                self.record.addi_events.push((event, record));
            }
            Opcode::SUB => {
                let record = RTypeRecord::new(record, instruction);
                self.record.sub_events.push((event, record));
            }
            Opcode::SUBW => {
                let record = RTypeRecord::new(record, instruction);
                self.record.subw_events.push((event, record));
            }
            Opcode::XOR | Opcode::OR | Opcode::AND => {
                let record = ALUTypeRecord::new(record, instruction);
                self.record.bitwise_events.push((event, record));
            }
            Opcode::SLL | Opcode::SLLW => {
                let record = ALUTypeRecord::new(record, instruction);
                self.record.shift_left_events.push((event, record));
            }
            Opcode::SRL | Opcode::SRA | Opcode::SRLW | Opcode::SRAW => {
                let record = ALUTypeRecord::new(record, instruction);
                self.record.shift_right_events.push((event, record));
            }
            Opcode::SLT | Opcode::SLTU => {
                let record = ALUTypeRecord::new(record, instruction);
                self.record.lt_events.push((event, record));
            }
            Opcode::MUL | Opcode::MULHU | Opcode::MULHSU | Opcode::MULH | Opcode::MULW => {
                let record = RTypeRecord::new(record, instruction);
                self.record.mul_events.push((event, record));
            }
            Opcode::DIVU
            | Opcode::REMU
            | Opcode::DIV
            | Opcode::REM
            | Opcode::DIVW
            | Opcode::DIVUW
            | Opcode::REMUW
            | Opcode::REMW => {
                let record = RTypeRecord::new(record, instruction);
                self.record.divrem_events.push((event, record));
            }
            _ => unreachable!(),
        }
    }

    /// Emit a jal event.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn emit_jal_event(
        &mut self,
        instruction: &Instruction,
        a: u64,
        b: u64,
        c: u64,
        record: &MemoryAccessRecord,
        op_a_0: bool,
        next_pc: u64,
    ) {
        if self.record.skip_writes {
            return;
        }
        let event = JumpEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            next_pc,
            opcode: instruction.opcode,
            a,
            b,
            c,
            op_a_0,
        };
        let record = JTypeRecord::new(record, instruction);
        self.record.jal_events.push((event, record));
    }

    /// Emit a jalr event.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn emit_jalr_event(
        &mut self,
        instruction: &Instruction,
        a: u64,
        b: u64,
        c: u64,
        record: &MemoryAccessRecord,
        op_a_0: bool,
        next_pc: u64,
    ) {
        if self.record.skip_writes {
            return;
        }
        let event = JumpEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            next_pc,
            opcode: instruction.opcode,
            a,
            b,
            c,
            op_a_0,
        };
        let record = ITypeRecord::new(record, instruction);
        self.record.jalr_events.push((event, record));
    }

    /// Emit a branch event.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn emit_branch_event(
        &mut self,
        instruction: &Instruction,
        a: u64,
        b: u64,
        c: u64,
        record: &MemoryAccessRecord,
        op_a_0: bool,
        next_pc: u64,
    ) {
        if self.record.skip_writes {
            return;
        }
        let event = BranchEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            next_pc,
            opcode: instruction.opcode,
            a,
            b,
            c,
            op_a_0,
        };
        let record = ITypeRecord::new(record, instruction);
        self.record.branch_events.push((event, record));
    }

    /// Emit a `UType` event.
    #[inline]
    fn emit_utype_event(
        &mut self,
        instruction: &Instruction,
        a: u64,
        b: u64,
        c: u64,
        record: &MemoryAccessRecord,
        op_a_0: bool,
    ) {
        if self.record.skip_writes {
            return;
        }
        let event = UTypeEvent {
            clk: self.core.clk(),
            pc: self.core.pc(),
            opcode: instruction.opcode,
            a,
            b,
            c,
            op_a_0,
        };
        let record = JTypeRecord::new(record, instruction);
        self.record.utype_events.push((event, record));
    }

    /// Emit a syscall event.
    #[allow(clippy::too_many_arguments)]
    fn emit_syscall_event(
        &mut self,
        clk: u64,
        syscall_code: SyscallCode,
        arg1: u64,
        arg2: u64,
        record: &MemoryAccessRecord,
        next_pc: u64,
        exit_code: u32,
        instruction: &Instruction,
        sig_return_pc_record: Option<MemoryReadRecord>,
        trap_result: Option<TrapResult>,
        trap_error: Option<TrapError>,
    ) {
        if self.record.skip_writes {
            return;
        }
        let syscall_event = self.syscall_event(
            clk,
            syscall_code,
            arg1,
            arg2,
            next_pc,
            exit_code,
            sig_return_pc_record,
            trap_result,
            trap_error,
        );

        let record = RTypeRecord::new(record, instruction);
        self.record.syscall_events.push((syscall_event, record));
    }
}

impl<'a, M: ExecutionMode> SyscallRuntime<'a, M> for TracingVM<'a, M> {
    const TRACING: bool = true;
    type Snapshot = ExecutionRecordSnapshot;

    fn core(&self) -> &CoreVM<'a, M, Self::Snapshot> {
        &self.core
    }

    fn core_mut(&mut self) -> &mut CoreVM<'a, M, Self::Snapshot> {
        &mut self.core
    }

    /// Create a syscall event.
    #[inline]
    fn syscall_event(
        &self,
        clk: u64,
        syscall_code: SyscallCode,
        arg1: u64,
        arg2: u64,
        next_pc: u64,
        exit_code: u32,
        sig_return_pc_record: Option<MemoryReadRecord>,
        trap_result: Option<TrapResult>,
        trap_error: Option<TrapError>,
    ) -> SyscallEvent {
        // should_send: if the syscall is usually sent and it is not manually set as internal.
        let should_send =
            syscall_code.should_send() != 0 && !self.core.is_retained_syscall(syscall_code);

        SyscallEvent {
            pc: self.core.pc(),
            next_pc,
            clk,
            should_send,
            syscall_code,
            syscall_id: syscall_code.syscall_id(),
            arg1,
            arg2,
            exit_code,
            sig_return_pc_record,
            trap_result,
            trap_error,
        }
    }

    fn add_precompile_event(
        &mut self,
        syscall_code: SyscallCode,
        syscall_event: SyscallEvent,
        event: PrecompileEvent,
    ) {
        self.record.precompile_events.add_event(syscall_code, syscall_event, event);
    }

    fn record_mut(&mut self) -> &mut ExecutionRecord {
        self.record
    }

    fn rr(&mut self, register: usize) -> MemoryReadRecord {
        let record = SyscallRuntime::rr(self.core_mut(), register);

        if let Some(local_memory_access) = &mut self.precompile_local_memory_access {
            local_memory_access.insert_record(register as u64, record);
        } else {
            self.local_memory_access.insert_record(register as u64, record);
        }

        record
    }

    fn rw(&mut self, register: usize, value: u64) -> MemoryWriteRecord {
        let record = SyscallRuntime::rw(self.core_mut(), register, value);

        if let Some(local_memory_access) = &mut self.precompile_local_memory_access {
            local_memory_access.insert_record(register as u64, record);
        } else {
            self.local_memory_access.insert_record(register as u64, record);
        }

        record
    }

    fn mr_without_prot(&mut self, addr: u64) -> MemoryReadRecord {
        let record = SyscallRuntime::mr_without_prot(self.core_mut(), addr);
        if let Some(local_memory_access) = &mut self.precompile_local_memory_access {
            local_memory_access.insert_record(addr, record);
        } else {
            self.local_memory_access.insert_record(addr, record);
        }

        record
    }

    fn mw_without_prot(&mut self, addr: u64) -> MemoryWriteRecord {
        let record = SyscallRuntime::mw_without_prot(self.core_mut(), addr);
        if let Some(local_memory_access) = &mut self.precompile_local_memory_access {
            local_memory_access.insert_record(addr, record);
        } else {
            self.local_memory_access.insert_record(addr, record);
        }
        record
    }

    fn page_prot_write(&mut self, page_idx: u64, prot: u8) -> PageProtRecord {
        let record = SyscallRuntime::page_prot_write(self.core_mut(), page_idx, prot);

        let clk = self.core().clk();
        if let Some(local_page_prot_access) = &mut self.precompile_local_page_prot_access {
            local_page_prot_access.insert_record(page_idx, record, clk, prot);
        } else {
            self.local_page_prot_access.insert_record(page_idx, record, clk, prot);
        }

        record
    }
}

#[derive(Debug, Default)]
pub struct LocalMemoryAccess {
    pub inner: HashMap<u64, MemoryLocalEvent>,
}

impl LocalMemoryAccess {
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn insert_record(&mut self, addr: u64, event: impl IntoMemoryRecord) {
        self.inner
            .entry(addr)
            .and_modify(|e| {
                let current_record = event.current_record();
                let previous_record = event.previous_record();

                // The latest record is the one with the highest timestamp.
                if current_record.timestamp > e.final_mem_access.timestamp {
                    e.final_mem_access = current_record;
                }

                // The initial record is the one with the lowest timestamp.
                if previous_record.timestamp < e.initial_mem_access.timestamp {
                    e.initial_mem_access = previous_record;
                }
            })
            .or_insert_with(|| MemoryLocalEvent {
                addr,
                initial_mem_access: event.previous_record(),
                final_mem_access: event.current_record(),
            });
    }
}

impl Deref for LocalMemoryAccess {
    type Target = HashMap<u64, MemoryLocalEvent>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for LocalMemoryAccess {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[derive(Debug, Default)]
pub struct LocalPageProtAccess {
    pub inner: HashMap<u64, PageProtLocalEvent>,
}

impl LocalPageProtAccess {
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn insert_record(
        &mut self,
        page_idx: u64,
        previous_record: PageProtRecord,
        clk: u64,
        value: u8,
    ) {
        self.inner
            .entry(page_idx)
            .and_modify(|e| e.final_page_prot_access.timestamp = clk)
            .or_insert(PageProtLocalEvent {
                page_idx,
                initial_page_prot_access: previous_record,
                final_page_prot_access: {
                    let mut final_prev_page_prot_record = previous_record;
                    final_prev_page_prot_record.timestamp = clk;
                    final_prev_page_prot_record.page_prot = value;
                    final_prev_page_prot_record
                },
            });
    }
}

pub struct PrecompileMemory<'a, 'b, M: ExecutionMode> {
    inner: &'b mut TracingVM<'a, M>,
}

impl<'a, 'b, M: ExecutionMode> PrecompileMemory<'a, 'b, M> {
    pub(crate) fn new(inner: &'b mut TracingVM<'a, M>) -> Self {
        Self { inner }
    }
}

impl<'a, M: ExecutionMode> SyscallRuntime<'a, M> for PrecompileMemory<'a, '_, M> {
    const TRACING: bool = true;
    type Snapshot = ExecutionRecordSnapshot;

    fn core(&self) -> &CoreVM<'a, M, Self::Snapshot> {
        self.inner.core()
    }

    fn core_mut(&mut self) -> &mut CoreVM<'a, M, Self::Snapshot> {
        self.inner.core_mut()
    }

    #[allow(clippy::too_many_arguments)]
    fn syscall_event(
        &self,
        clk: u64,
        syscall_code: SyscallCode,
        arg1: u64,
        arg2: u64,
        next_pc: u64,
        exit_code: u32,
        sig_return_pc_record: Option<MemoryReadRecord>,
        trap_result: Option<TrapResult>,
        trap_error: Option<TrapError>,
    ) -> SyscallEvent {
        self.inner.syscall_event(
            clk,
            syscall_code,
            arg1,
            arg2,
            next_pc,
            exit_code,
            sig_return_pc_record,
            trap_result,
            trap_error,
        )
    }

    fn add_precompile_event(
        &mut self,
        syscall_code: SyscallCode,
        syscall_event: SyscallEvent,
        event: PrecompileEvent,
    ) {
        self.inner.add_precompile_event(syscall_code, syscall_event, event);
    }

    fn record_mut(&mut self) -> &mut ExecutionRecord {
        self.inner.record_mut()
    }

    fn postprocess_precompile(&mut self) -> (Vec<MemoryLocalEvent>, Vec<PageProtLocalEvent>) {
        let mut precompile_local_memory_access = Vec::new();
        if let Some(local_memory_access) = &mut self.inner.precompile_local_memory_access {
            for (addr, event) in local_memory_access.drain() {
                if let Some(cpu_mem_access) = self.inner.local_memory_access.remove(&addr) {
                    self.inner.record.cpu_local_memory_access.push(cpu_mem_access);
                }
                precompile_local_memory_access.push(event);
            }
        }

        let mut precompile_local_page_prot_access = Vec::new();
        if let Some(local_page_prot_access) = &mut self.inner.precompile_local_page_prot_access {
            for (page_idx, event) in local_page_prot_access.inner.drain() {
                if let Some(cpu_page_prot_access) =
                    self.inner.local_page_prot_access.inner.remove(&page_idx)
                {
                    self.inner.record.cpu_local_page_prot_access.push(cpu_page_prot_access);
                }

                precompile_local_page_prot_access.push(event);
            }
        }

        (precompile_local_memory_access, precompile_local_page_prot_access)
    }

    fn page_prot_write(&mut self, page_idx: u64, prot: u8) -> PageProtRecord {
        let prev_page_prot_record = self.inner.page_prot_write(page_idx, prot);

        let clk = self.inner.core.clk();
        if let Some(local_page_prot_access) = &mut self.inner.precompile_local_page_prot_access {
            local_page_prot_access.insert_record(page_idx, prev_page_prot_record, clk, prot);
        }
        assert!(self.inner.precompile_local_page_prot_access.is_some());
        assert!(self.inner.precompile_local_page_prot_access.as_ref().unwrap().inner.len() == 1);

        prev_page_prot_record
    }

    fn page_prot_range_check(
        &mut self,
        start_page_idx: u64,
        end_page_idx: u64,
        page_prot_bitmap: u8,
    ) -> (Vec<PageProtRecord>, Option<TrapError>) {
        let (records, error) =
            self.inner.page_prot_range_check(start_page_idx, end_page_idx, page_prot_bitmap);
        let clk = self.inner.core.clk();
        for record in &records {
            if let Some(local_page_prot_access) = &mut self.inner.precompile_local_page_prot_access
            {
                local_page_prot_access.insert_record(
                    record.page_idx,
                    *record,
                    clk,
                    record.page_prot,
                );
            } else {
                self.inner.local_page_prot_access.insert_record(
                    record.page_idx,
                    *record,
                    clk,
                    record.page_prot,
                );
            }
        }
        (records, error)
    }

    fn rr(&mut self, reg_no: usize) -> MemoryReadRecord {
        debug_assert!(reg_no < 32, "out of bounds register: {reg_no}");

        let current_clk = self.inner.core.clk();
        let registers = self.inner.core.registers_mut();
        let old_record = registers[reg_no];
        let new_record = MemoryRecord { timestamp: current_clk, value: old_record.value };
        registers[reg_no] = new_record;

        let record = MemoryReadRecord {
            value: old_record.value,
            timestamp: self.inner.core.clk(),
            prev_timestamp: old_record.timestamp,
            prev_page_prot_record: None,
        };

        let reg_no = reg_no as u64;
        if let Some(local_memory_access) = &mut self.inner.precompile_local_memory_access {
            local_memory_access.insert_record(reg_no, record);
        } else {
            self.inner.local_memory_access.insert_record(reg_no, record);
        }

        record
    }

    fn rw(&mut self, reg_no: usize, value: u64) -> MemoryWriteRecord {
        debug_assert!(reg_no < 32, "out of bounds register: {reg_no}");

        let current_clk = self.inner.core.timestamp(MemoryAccessPosition::A);
        let registers = self.inner.core.registers_mut();
        let old_record = registers[reg_no];
        let new_record = MemoryRecord { timestamp: current_clk, value };
        registers[reg_no] = new_record;

        let record = MemoryWriteRecord {
            value,
            timestamp: current_clk,
            prev_timestamp: old_record.timestamp,
            prev_value: old_record.value,
            prev_page_prot_record: None,
        };

        let reg_no = reg_no as u64;
        if let Some(local_memory_access) = &mut self.inner.precompile_local_memory_access {
            local_memory_access.insert_record(reg_no, record);
        } else {
            self.inner.local_memory_access.insert_record(reg_no, record);
        }

        record
    }

    fn mr_without_prot(&mut self, addr: u64) -> MemoryReadRecord {
        let record = self.inner.mr_without_prot(addr);

        if let Some(local_memory_access) = &mut self.inner.precompile_local_memory_access {
            local_memory_access.insert_record(addr, record);
        } else {
            self.inner.local_memory_access.insert_record(addr, record);
        }

        record
    }

    fn mr_slice_without_prot(&mut self, addr: u64, len: usize) -> Vec<MemoryReadRecord> {
        let records = self.inner.mr_slice_without_prot(addr, len);
        for (i, record) in records.iter().enumerate() {
            if let Some(local_memory_access) = &mut self.inner.precompile_local_memory_access {
                local_memory_access.insert_record(addr + i as u64 * 8, *record);
            } else {
                self.inner.local_memory_access.insert_record(addr + i as u64 * 8, *record);
            }
        }
        records
    }

    fn mw_slice_without_prot(&mut self, addr: u64, len: usize) -> Vec<MemoryWriteRecord> {
        let records = self.inner.mw_slice_without_prot(addr, len);
        for (i, record) in records.iter().enumerate() {
            if let Some(local_memory_access) = &mut self.inner.precompile_local_memory_access {
                local_memory_access.insert_record(addr + i as u64 * 8, *record);
            } else {
                self.inner.local_memory_access.insert_record(addr + i as u64 * 8, *record);
            }
        }
        records
    }

    fn mw_without_prot(&mut self, addr: u64) -> MemoryWriteRecord {
        let record = self.inner.mw_without_prot(addr);

        if let Some(local_memory_access) = &mut self.inner.precompile_local_memory_access {
            local_memory_access.insert_record(addr, record);
        } else {
            self.inner.local_memory_access.insert_record(addr, record);
        }

        record
    }
}

/// Wrapper enum to handle `TracingVM` with different execution modes at runtime.
pub enum TracingVMEnum<'a> {
    /// `TracingVM` for `SupervisorMode`.
    Supervisor(TracingVM<'a, SupervisorMode>),
    /// `TracingVM` for `UserMode`.
    User(TracingVM<'a, UserMode>),
}

impl<'a> TracingVMEnum<'a> {
    /// Create a new `TracingVMEnum` based on program's `enable_untrusted_programs` flag.
    pub fn new<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        opts: SP1CoreOpts,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        record: &'a mut ExecutionRecord,
    ) -> Self {
        if program.enable_untrusted_programs {
            Self::User(TracingVM::<UserMode>::new(trace, program, opts, proof_nonce, record))
        } else {
            Self::Supervisor(TracingVM::<SupervisorMode>::new(
                trace,
                program,
                opts,
                proof_nonce,
                record,
            ))
        }
    }

    /// Execute the program until it halts or reaches a shard boundary.
    pub fn execute(&mut self) -> Result<CycleResult, ExecutionError> {
        match self {
            Self::Supervisor(vm) => vm.execute(),
            Self::User(vm) => vm.execute(),
        }
    }

    /// Get the public values.
    #[must_use]
    pub fn public_values(&self) -> &PublicValues<u32, u64, u64, u32> {
        match self {
            Self::Supervisor(vm) => vm.public_values(),
            Self::User(vm) => vm.public_values(),
        }
    }

    /// Get the current clock.
    #[must_use]
    pub fn clk(&self) -> u64 {
        match self {
            Self::Supervisor(vm) => vm.core.clk(),
            Self::User(vm) => vm.core.clk(),
        }
    }

    /// Get the current PC.
    #[must_use]
    pub fn pc(&self) -> u64 {
        match self {
            Self::Supervisor(vm) => vm.core.pc(),
            Self::User(vm) => vm.core.pc(),
        }
    }

    /// Get the registers.
    #[must_use]
    pub fn registers(&self) -> &[MemoryRecord; 32] {
        match self {
            Self::Supervisor(vm) => vm.core.registers(),
            Self::User(vm) => vm.core.registers(),
        }
    }

    /// Get the record.
    #[must_use]
    pub fn record(&self) -> &ExecutionRecord {
        match self {
            Self::Supervisor(vm) => vm.record,
            Self::User(vm) => vm.record,
        }
    }

    /// Get the record mutably.
    #[must_use]
    pub fn record_mut(&mut self) -> &mut ExecutionRecord {
        match self {
            Self::Supervisor(vm) => vm.record,
            Self::User(vm) => vm.record,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use powdr_autoprecompiles::execution::{
        OptimisticConstraint, OptimisticConstraints, OptimisticExpression, OptimisticLiteral,
    };

    use crate::{
        utils::add_halt, Apc, CycleResult, ExecutionRecord, Instruction, MinimalExecutor, Opcode,
        Program, Register, SP1Context, SP1CoreOpts, SupervisorMode, TracingVM,
    };

    fn run_tracing_vm(
        program: Arc<Program>,
        opts: SP1CoreOpts,
        max_trace_size: u64,
    ) -> (ExecutionRecord, [crate::events::MemoryRecord; 32], CycleResult) {
        let mut minimal =
            MinimalExecutor::<SupervisorMode>::tracing(program.clone(), max_trace_size);
        let chunk = minimal.execute_chunk().expect("trace chunk");

        let proof_nonce = SP1Context::default().proof_nonce;
        let mut record =
            ExecutionRecord::new(program.clone(), proof_nonce, opts.global_dependencies_opt);
        let mut vm =
            TracingVM::<SupervisorMode>::new(&chunk, program, opts, proof_nonce, &mut record);
        let status = vm.execute().unwrap();

        let registers = *vm.core.registers();
        (record, registers, status)
    }

    #[test]
    fn test_add_apc() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        //     addi x27, x0, 5
        //     addi x28, x0, 37
        //     add x26, x28, x27

        // Note that compared to the `test_add` test, we use `Opcode::ADDI` instead of `Opcode::ADD`
        // This is found somewhere else in the codebase
        // Without this change, `Trace` mode fails.

        let mut original_instructions = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
            Instruction::new(Opcode::ADDI, 27, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 28, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 26, 28, 27, false, false),
        ];
        add_halt(&mut original_instructions);

        let program_without_apcs = Program::new(original_instructions, 0, 0);

        // Test with different APC ranges
        for apc_range_and_cost in
            [vec![], vec![(&(0, 2), 1), (&(3, 5), 1)], vec![(&(0, 1), 1), (&(3, 4), 1)]]
                .into_iter()
                .map(|v| {
                    v.into_iter()
                        .map(|(x, y)| {
                            Apc::new(x, y, OptimisticConstraints::from_constraints(vec![]))
                        })
                        .collect::<Vec<_>>()
                })
        {
            let should_execute_apcs = !apc_range_and_cost.is_empty();
            // Here we set APC costs to a dummy [1, 1] if there are APCs
            let program = if should_execute_apcs {
                program_without_apcs.clone().with_apcs(apc_range_and_cost)
            } else {
                program_without_apcs.clone()
            };

            let program = Arc::new(program);
            let (record, registers, status) =
                run_tracing_vm(program, SP1CoreOpts::default(), 100_000);
            assert!(status.is_done(), "TracingVM did not complete");

            assert_eq!(registers[Register::X31 as usize].value, 42);
            assert_eq!(registers[Register::X26 as usize].value, 42);
            // Check that the APCs were executed iff there were any
            assert_eq!(!record.apc_invocations.is_empty(), should_execute_apcs);
        }
    }

    #[test]
    fn test_apc_loop() {
        // main:
        //     addi x29, x0, 2
        //     addi x30, x0, 0
        // loop:
        //     addi x30, x30, 1
        //     addi x29, x29, -1
        //     bne x29, x0, -8
        //     addi x31, x30, 0
        let mut instructions = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 2, false, true),
            Instruction::new(Opcode::ADDI, 30, 0, 0, false, true),
            Instruction::new(Opcode::ADDI, 30, 30, 1, false, true),
            Instruction::new(Opcode::ADDI, 29, 29, u64::MAX, false, true),
            Instruction::new(Opcode::BNE, 29, 0, 0u64.wrapping_sub(8), false, true),
            Instruction::new(Opcode::ADDI, 31, 30, 0, false, true),
        ];
        add_halt(&mut instructions);

        let program_without_apcs = Program::new(instructions, 0, 0);
        let apc_range_and_cost = vec![Apc::new(&(2, 4), 1, OptimisticConstraints::empty())];
        let program = Arc::new(program_without_apcs.with_apcs(apc_range_and_cost));
        let (record, registers, status) = run_tracing_vm(program, SP1CoreOpts::default(), 100_000);
        assert!(status.is_done(), "TracingVM did not complete");

        assert_eq!(registers[Register::X30 as usize].value, 2);
        assert_eq!(registers[Register::X31 as usize].value, 2);
        assert_eq!(record.apc_invocations.len(), 2);
    }

    #[test]
    fn test_failed_add_apc() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        //     addi x27, x0, 5
        //     addi x28, x0, 37
        //     add x26, x28, x27

        let mut original_instructions = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
            Instruction::new(Opcode::ADDI, 27, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 28, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 26, 28, 27, false, false),
        ];
        add_halt(&mut original_instructions);

        let program_without_apcs = Program::new(original_instructions, 0, 0);

        // A failling constraint that `x3[0] == 123`
        let failing_optimistic_constraints = || {
            OptimisticConstraints::from_constraints(vec![OptimisticConstraint {
                left: OptimisticExpression::Literal(OptimisticLiteral {
                    instr_idx: 0,
                    val: powdr_autoprecompiles::execution::LocalOptimisticLiteral::RegisterLimb(
                        3, 0,
                    ),
                }),
                right: OptimisticExpression::Number(123),
            }])
        };

        // Test with different APC ranges
        for apc_range_and_cost in
            [vec![], vec![(&(0, 2), 1), (&(3, 5), 1)], vec![(&(0, 1), 1), (&(3, 4), 1)]]
                .into_iter()
                .map(|v| {
                    v.into_iter()
                        .map(|(x, y)| Apc::new(x, y, failing_optimistic_constraints()))
                        .collect::<Vec<_>>()
                })
        {
            let should_execute_apcs = !apc_range_and_cost.is_empty();
            // Here we set APC costs to a dummy [1, 1] if there are APCs
            let program = if should_execute_apcs {
                program_without_apcs.clone().with_apcs(apc_range_and_cost)
            } else {
                program_without_apcs.clone()
            };

            let (record, registers, status) =
                run_tracing_vm(Arc::new(program), SP1CoreOpts::default(), 100_000);
            assert!(status.is_done(), "TracingVM did not complete");
            assert_eq!(registers[Register::X31 as usize].value, 42);
            assert_eq!(registers[Register::X26 as usize].value, 42);
            // Check that the APCs were executed iff there were any
            assert!(record.apc_invocations.is_empty());
        }
    }

    #[test]
    fn test_multiple_apc_conflict() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        //     addi x27, x0, 5
        //     addi x28, x0, 37
        //     add x26, x28, x27

        let mut original_instructions = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
            Instruction::new(Opcode::ADDI, 27, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 28, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 26, 28, 27, false, false),
        ];
        add_halt(&mut original_instructions);

        let program_without_apcs = Program::new(original_instructions, 0, 0);

        // Pass the same apc twice
        for apc_range_and_cost in [vec![(&(0, 2), 1), (&(0, 2), 1)]].into_iter().map(|v| {
            v.into_iter()
                .map(|(x, y)| Apc::new(x, y, OptimisticConstraints::from_constraints(vec![])))
                .collect::<Vec<_>>()
        }) {
            // Here we set APC costs to a dummy [1, 1] if there are APCs
            let program = program_without_apcs.clone().with_apcs(apc_range_and_cost);

            let (record, registers, status) =
                run_tracing_vm(Arc::new(program), SP1CoreOpts::default(), 100_000);
            assert!(status.is_done(), "TracingVM did not complete");
            assert_eq!(registers[Register::X31 as usize].value, 42);
            assert_eq!(registers[Register::X26 as usize].value, 42);
            // Check that only the first apc was executed (priority is based on insertion order)
            assert_eq!(record.apc_invocations.len(), 1);
            assert_eq!(record.apc_event_count(0), 1);
            assert!(!record.has_apc_events(1));
        }
    }

    #[test]
    fn test_multiple_apc_fallback() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        //     addi x27, x0, 5
        //     addi x28, x0, 37
        //     add x26, x28, x27

        let mut original_instructions = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
            Instruction::new(Opcode::ADDI, 27, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 28, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 26, 28, 27, false, false),
        ];
        add_halt(&mut original_instructions);

        let program_without_apcs = Program::new(original_instructions, 0, 0);

        // Pass A, B and AB
        // Have AB fail at the last step (wrong pc) and make sure A and B are returned
        let apc_range_and_cost = vec![
            (
                &(0, 4),
                1,
                OptimisticConstraints::from_constraints(vec![OptimisticConstraint {
                    left: OptimisticExpression::Literal(OptimisticLiteral {
                        instr_idx: 4,
                        val: powdr_autoprecompiles::execution::LocalOptimisticLiteral::Pc,
                    }),
                    right: OptimisticExpression::Number(42),
                }]),
            ),
            (&(0, 2), 1, OptimisticConstraints::empty()),
            (&(2, 4), 1, OptimisticConstraints::empty()),
        ]
        .into_iter()
        .map(|(range, cost, constraints)| Apc::new(range, cost, constraints));

        let program = program_without_apcs.clone().with_apcs(apc_range_and_cost);

        let (record, registers, status) =
            run_tracing_vm(Arc::new(program), SP1CoreOpts::default(), 100_000);
        assert!(status.is_done(), "TracingVM did not complete");
        assert_eq!(registers[Register::X31 as usize].value, 42);
        assert_eq!(registers[Register::X26 as usize].value, 42);
        // Check that AB was not executed but A and B were
        assert_eq!(record.apc_invocations.len(), 2);
        assert!(!record.has_apc_events(0));
        assert_eq!(record.apc_event_count(1), 1);
        assert_eq!(record.apc_event_count(2), 1);
    }

    #[test]
    fn test_multiple_apc_fallback_branch_pc_constraint() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     beq x29, x30, +8
        //     add x31, x30, x29
        //     addi x27, x0, 5
        //     addi x28, x0, 37
        //     add x26, x28, x27

        let mut original_instructions = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 30, 0, 37, false, true),
            Instruction::new(Opcode::BEQ, 29, 30, 8, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
            Instruction::new(Opcode::ADDI, 27, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 28, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 26, 28, 27, false, false),
        ];
        add_halt(&mut original_instructions);

        let program_without_apcs = Program::new(original_instructions, 0, 0);

        // Pass A, B and AB
        // Have AB succeed and cancel A and B, with a pc constraint at the end of A.
        let apc_range_and_cost = vec![
            (
                &(0, 7),
                1,
                OptimisticConstraints::from_constraints(vec![OptimisticConstraint {
                    left: OptimisticExpression::Literal(OptimisticLiteral {
                        instr_idx: 3,
                        val: powdr_autoprecompiles::execution::LocalOptimisticLiteral::Pc,
                    }),
                    right: OptimisticExpression::Number(12),
                }]),
            ),
            (&(0, 3), 1, OptimisticConstraints::empty()),
            (&(3, 7), 1, OptimisticConstraints::empty()),
        ]
        .into_iter()
        .map(|(range, cost, constraints)| Apc::new(range, cost, constraints));

        let program = program_without_apcs.clone().with_apcs(apc_range_and_cost);

        let (record, registers, status) =
            run_tracing_vm(Arc::new(program), SP1CoreOpts::default(), 100_000);
        assert!(status.is_done(), "TracingVM did not complete");
        assert_eq!(registers[Register::X31 as usize].value, 42);
        assert_eq!(registers[Register::X26 as usize].value, 42);
        // Check that AB executed and A/B were cancelled.
        assert_eq!(record.apc_invocations.len(), 1);
        assert_eq!(record.apc_event_count(0), 1);
        assert!(!record.has_apc_events(1));
        assert!(!record.has_apc_events(2));
    }

    #[test]
    fn test_apc_state_bump_error() {
        // This test verifies that when a state bump (bump2) occurs during an APC,
        // the APC is properly rejected and a state_bump_error is recorded.
        //
        // There are two types of state bumps:
        // - bump1: Clock overflow - triggers when clk's top 24 bits change (requires ~2M cycles)
        // - bump2: PC overflow - triggers when PC crosses a 16-bit boundary (testable with pc_base)
        //
        // Memory bump also requires clk to reach 2^24 (~2M cycles), making it impractical
        // to test with unit tests. However, the APC rejection logic is identical for all
        // bump types (comparing event count in from_snapshot vs to_snapshot), so this test
        // validates the shared code path.
        //
        // This test uses bump2 by setting pc_base = 0xFFF0, so instruction 3 (at PC 0xFFFC)
        // will cause next_pc = 0x10000, crossing the 16-bit boundary.
        //
        // Instruction layout:
        //   Index 0: PC = 0xFFF0
        //   Index 1: PC = 0xFFF4
        //   Index 2: PC = 0xFFF8
        //   Index 3: PC = 0xFFFC -> next_pc = 0x10000 (bump2 triggers here!)
        //   Index 4: PC = 0x10000
        //   Index 5: PC = 0x10004
        //   Index 6: PC = 0x10008
        //   Index 7: PC = 0x1000C

        let mut instructions: Vec<Instruction> = std::iter::repeat([
            Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 30, 0, 8, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ])
        .flatten()
        .take(12)
        .collect();

        add_halt(&mut instructions);

        // Set pc_base = 0xFFF0 so that instruction 3 triggers bump2
        let pc_base: u64 = 0xFFF0;
        let program_without_apcs = Program::new(instructions, pc_base, pc_base);

        // Create an APC covering instructions 0-7 which spans the bump point at index 3
        let apc_range_and_cost =
            vec![Apc::new(&(0, 7), 1, OptimisticConstraints::from_constraints(vec![]))];

        let program = program_without_apcs.with_apcs(apc_range_and_cost);

        let (record, _registers, status) =
            run_tracing_vm(Arc::new(program), SP1CoreOpts::default(), 100_000);
        assert!(status.is_done(), "TracingVM did not complete");
        assert!(
            record.apc_invocations.is_empty(),
            "Expected APC to be rejected when a state bump occurs"
        );
    }

    /// Build a program that runs a tight loop to cross the `clk_high` epoch boundary (clk >= 2^24),
    /// then executes post-loop instructions. Post-loop starts at index 5.
    ///
    /// Layout:
    ///   0: LUI x10, <upper>           ; load loop counter (~2.1M)
    ///   1: ADDI x10, x10, <lower>     ; add lower bits
    ///   2: ADDI x11, x0, 42           ; touch x11 BEFORE the epoch boundary
    ///   3: ADDI x10, x10, -1          ; decrement counter (loop body)
    ///   4: BNE x10, x0, -4            ; branch back to index 3 if x10 != 0
    ///   5: ADDI x12, x11, 1           ; post-loop: read x11 (stale, last touched in epoch 0)
    ///   6: ADDI x13, x12, 1           ; post-loop: another instruction
    ///   7: ADDI x14, x13, 1           ; post-loop: another instruction
    ///   8..11: halt
    fn build_epoch_crossing_program() -> Program {
        // We need ~2,097,152 cycles to cross the epoch boundary (2^24 / CLK_INC=8).
        // Use 2,100,000 to be safe.
        let loop_count: u64 = 2_100_000;
        let upper = loop_count & !0xFFF; // upper bits for LUI
        let lower = (loop_count & 0xFFF) as i32; // lower 12 bits for ADDI

        let mut instructions = vec![
            // Index 0: LUI x10, upper
            Instruction::new(Opcode::LUI, 10, upper, 0, true, true),
            // Index 1: ADDI x10, x10, lower
            Instruction::new(Opcode::ADDI, 10, 10, lower as u64, false, true),
            // Index 2: ADDI x11, x0, 42 — touch x11 before the epoch boundary
            Instruction::new(Opcode::ADDI, 11, 0, 42, false, true),
            // Index 3: ADDI x10, x10, -1 — loop body (decrement)
            Instruction::new(Opcode::ADDI, 10, 10, (-1i64) as u64, false, true),
            // Index 4: BNE x10, x0, -4 — branch back to index 3
            Instruction::new(Opcode::BNE, 10, 0, (-4i64) as u64, false, true),
            // Index 5: ADDI x12, x11, 1 — post-loop: reads x11 (stale from epoch 0)
            Instruction::new(Opcode::ADDI, 12, 11, 1, false, true),
            // Index 6: ADDI x13, x12, 1
            Instruction::new(Opcode::ADDI, 13, 12, 1, false, true),
            // Index 7: ADDI x14, x13, 1
            Instruction::new(Opcode::ADDI, 14, 13, 1, false, true),
        ];

        add_halt(&mut instructions);

        Program::new(instructions, 0u64, 0u64)
    }

    #[test]
    fn test_apc_memory_bump_error() {
        // Test that an APC is aborted when it accesses a register whose previous timestamp
        // is in a different clk_high epoch (memory bump), even though the APC's own
        // instructions don't cross an epoch boundary.
        //
        // Setup: x11 is touched at index 2 (epoch 0, clk ~ 24). After ~2.1M loop iterations
        // the loop exits in epoch 1. Post-loop index 5 reads x11, whose prev_timestamp is
        // still in epoch 0 → triggers pending_memory_bump → APC aborted.
        let program_without_apcs = build_epoch_crossing_program();

        // APC covers only post-loop instructions (indices 5-7), all within epoch 1.
        // No clk_high boundary is crossed, but index 5 reads x11 which was last accessed
        // in epoch 0, triggering a memory bump event.
        let apc = vec![Apc::new(&(5, 8), 1, OptimisticConstraints::from_constraints(vec![]))];
        let program = program_without_apcs.with_apcs(apc);

        let (record, registers, status) =
            run_tracing_vm(Arc::new(program), SP1CoreOpts::default(), 10_000_000);
        assert!(status.is_done(), "TracingVM did not complete");
        // Verify the program computed correctly (x11=42, x12=43, x13=44, x14=45)
        assert_eq!(registers[11].value, 42);
        assert_eq!(registers[12].value, 43);
        assert_eq!(registers[13].value, 44);
        assert_eq!(registers[14].value, 45);
        // The APC covering indices 5-7 should be rejected because index 5 reads x11
        // whose prev_timestamp is in epoch 0 while the current clk is in epoch 1.
        assert!(
            record.apc_invocations.is_empty(),
            "Expected APC to be rejected due to memory bump (stale register access across epoch)"
        );
    }
}
