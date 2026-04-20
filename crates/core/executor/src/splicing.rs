use std::{marker::PhantomData, sync::Arc};

use serde::Serialize;
use sp1_hypercube::air::PROOF_NONCE_NUM_WORDS;
use sp1_jit::{MemReads, MemValue, MinimalTrace, TraceChunk};
use sp1_primitives::consts::LOG_PAGE_SIZE;

use crate::{
    events::{MemoryReadRecord, MemoryRecord, MemoryWriteRecord, PageProtRecord},
    vm::{
        memory::{CompressedMemory, CompressedPages},
        results::{
            CycleResult, FetchResult, LoadResult, LoadResultSupervisor, StoreResult,
            StoreResultSupervisor, TrapResult,
        },
        shapes::{ShapeChecker, HALT_AREA, HALT_HEIGHT},
        syscall::SyscallRuntime,
        CoreVM,
    },
    ExecutionError, ExecutionMode, Instruction, Opcode, Program, SP1CoreOpts, ShardingThreshold,
    SupervisorMode, SyscallCode, TrapError, UserMode,
};

/// A RISC-V VM that uses a [`MinimalTrace`] to create multiple [`SplicedMinimalTrace`]s.
///
/// These new [`SplicedMinimalTrace`]s correspond to exactly 1 execuction shard to be proved.
///
/// Note that this is the only time we account for trace area throught the execution pipeline.
///
/// The type parameter `M` determines whether page protection checks are enabled.
pub struct SplicingVM<'a, M: ExecutionMode> {
    /// The core VM.
    pub core: CoreVM<'a, M>,
    /// The shape checker, responsible for cutting the execution when a shard limit is reached.
    pub shape_checker: ShapeChecker<M>,
    /// The addresses that have been touched.
    pub touched_addresses: &'a mut CompressedMemory,
    /// The page indices that have been touched (for page protection tracking).
    pub touched_pages: &'a mut CompressedPages,
    /// Phantom data for the execution mode.
    _mode: PhantomData<M>,
}

impl SplicingVM<'_, SupervisorMode> {
    /// Execute the program until it halts.
    pub fn execute(&mut self) -> Result<CycleResult, ExecutionError> {
        if self.core.is_done() {
            return Ok(CycleResult::Done(true));
        }

        loop {
            let mut result = self.execute_instruction()?;

            // If we're not already done, ensure that we don't have a shard boundary.
            if !result.is_done() && self.shape_checker.check_shard_limit() {
                result = CycleResult::ShardBoundary;
            }

            match result {
                CycleResult::Done(false) => {}
                CycleResult::ShardBoundary | CycleResult::TraceEnd => {
                    self.start_new_shard();
                    return Ok(CycleResult::ShardBoundary);
                }
                CycleResult::Done(true) => {
                    return Ok(CycleResult::Done(true));
                }
            }
        }
    }

    /// Execute the next instruction at the current PC.
    pub fn execute_instruction(&mut self) -> Result<CycleResult, ExecutionError> {
        let instruction = self.core.fetch();

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
                self.execute_alu(&instruction);
            }
            Opcode::LB
            | Opcode::LBU
            | Opcode::LH
            | Opcode::LHU
            | Opcode::LW
            | Opcode::LWU
            | Opcode::LD => self.execute_load(&instruction)?,
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => {
                self.execute_store(&instruction)?;
            }
            Opcode::JAL | Opcode::JALR => {
                self.execute_jump(&instruction);
            }
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                self.execute_branch(&instruction);
            }
            Opcode::LUI | Opcode::AUIPC => {
                self.execute_utype(&instruction);
            }
            Opcode::ECALL => self.execute_ecall(&instruction)?,
            Opcode::EBREAK | Opcode::UNIMP => {
                unreachable!("Invalid opcode for `execute_instruction`: {:?}", instruction.opcode)
            }
        }

        self.shape_checker.handle_instruction(
            &instruction,
            self.core.needs_bump_clk_high(),
            instruction.is_alu_instruction() && instruction.op_a == 0,
            instruction.is_memory_load_instruction() && instruction.op_a == 0,
            self.core.needs_state_bump(&instruction),
        );

        Ok(self.core.advance())
    }
}

impl SplicingVM<'_, SupervisorMode> {
    /// Execute a load instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the load instruction.
    #[inline]
    pub fn execute_load(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let LoadResultSupervisor { addr, mr_record, .. } = self.core.execute_load(instruction)?;

        self.touched_addresses.insert(addr & !0b111, true);
        self.shape_checker.handle_mem_event(addr, mr_record.prev_timestamp);

        Ok(())
    }

    /// Execute a store instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the store instruction.
    #[inline]
    pub fn execute_store(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let StoreResultSupervisor { addr, mw_record, .. } = self.core.execute_store(instruction)?;

        self.touched_addresses.insert(addr & !0b111, true);
        self.shape_checker.handle_mem_event(addr, mw_record.prev_timestamp);

        Ok(())
    }
}

impl SplicingVM<'_, UserMode> {
    /// Execute the program until it halts.
    pub fn execute(&mut self) -> Result<CycleResult, ExecutionError> {
        if self.core.is_done() {
            return Ok(CycleResult::Done(true));
        }

        loop {
            let mut result = self.execute_instruction()?;

            // If we're not already done, ensure that we don't have a shard boundary.
            if !result.is_done() && self.shape_checker.check_shard_limit() {
                result = CycleResult::ShardBoundary;
            }

            match result {
                CycleResult::Done(false) => {}
                CycleResult::ShardBoundary | CycleResult::TraceEnd => {
                    self.start_new_shard();
                    return Ok(CycleResult::ShardBoundary);
                }
                CycleResult::Done(true) => {
                    return Ok(CycleResult::Done(true));
                }
            }
        }
    }

    /// Execute the next instruction at the current PC.
    pub fn execute_instruction(&mut self) -> Result<CycleResult, ExecutionError> {
        let FetchResult { instruction, mr_record, pc, error } = self.core.fetch()?;
        let mut num_page_prot_accesses = 0;

        if let Some(error) = error {
            self.handle_error(error)?;
            let page_idx = pc >> LOG_PAGE_SIZE;
            self.shape_checker.handle_page_prot_event(
                page_idx,
                mr_record.unwrap().prev_page_prot_record.unwrap().timestamp,
            );
            self.touched_pages.insert(page_idx, true);
            num_page_prot_accesses += 1;
            self.shape_checker.handle_trap_exec_event();
            self.shape_checker
                .handle_trap_events(self.core().needs_bump_clk_high(), num_page_prot_accesses);
            return Ok(self.core.advance());
        }

        if instruction.is_none() {
            unreachable!("Fetching the next instruction failed");
        }

        if let Some(mr_record) = mr_record {
            let instruction_value = (mr_record.value >> ((pc % 8) * 8)) as u32;
            self.touched_addresses.insert(pc & !0b111, true);
            self.shape_checker.handle_untrusted_instruction(instruction_value);
            self.shape_checker.handle_mem_event(pc & !0b111, mr_record.prev_timestamp);
            let page_idx = pc >> LOG_PAGE_SIZE;
            self.shape_checker.handle_page_prot_event(
                page_idx,
                mr_record.prev_page_prot_record.unwrap().timestamp,
            );
            self.touched_pages.insert(page_idx, true);
            num_page_prot_accesses += 1;
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
                self.execute_alu(&instruction);
            }
            Opcode::LB
            | Opcode::LBU
            | Opcode::LH
            | Opcode::LHU
            | Opcode::LW
            | Opcode::LWU
            | Opcode::LD => self.execute_load(&instruction)?,
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => {
                self.execute_store(&instruction)?;
            }
            Opcode::JAL | Opcode::JALR => {
                self.execute_jump(&instruction);
            }
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                self.execute_branch(&instruction);
            }
            Opcode::LUI | Opcode::AUIPC => {
                self.execute_utype(&instruction);
            }
            Opcode::ECALL => self.execute_ecall(&instruction)?,
            Opcode::EBREAK | Opcode::UNIMP => {
                unreachable!("Invalid opcode for `execute_instruction`: {:?}", instruction.opcode)
            }
        }

        if instruction.is_memory_load_instruction() || instruction.is_memory_store_instruction() {
            num_page_prot_accesses += 1;
        }

        self.shape_checker.handle_instruction(
            &instruction,
            self.core.needs_bump_clk_high(),
            instruction.is_alu_instruction() && instruction.op_a == 0,
            instruction.is_memory_load_instruction() && instruction.op_a == 0,
            self.core.needs_state_bump(&instruction),
            num_page_prot_accesses,
        );

        Ok(self.core.advance())
    }
}

impl SplicingVM<'_, UserMode> {
    /// Execute a load instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the load instruction.
    #[inline]
    pub fn execute_load(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let LoadResult { addr, mr_record, error, .. } = self.core.execute_load(instruction)?;

        if let Some(error) = error {
            self.handle_error(error)?;
            self.shape_checker.handle_trap_mem_event();
        } else {
            self.touched_addresses.insert(addr & !0b111, true);
            self.shape_checker.handle_mem_event(addr, mr_record.prev_timestamp);
        }

        if let Some(record) = mr_record.prev_page_prot_record {
            self.shape_checker.handle_page_prot_event(record.page_idx, record.timestamp);
            self.touched_pages.insert(record.page_idx, true);
        }

        Ok(())
    }

    /// Execute a store instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the store instruction.
    #[inline]
    pub fn execute_store(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let StoreResult { addr, mw_record, error, .. } = self.core.execute_store(instruction)?;

        if let Some(error) = error {
            self.handle_error(error)?;
            self.shape_checker.handle_trap_mem_event();
        } else {
            self.touched_addresses.insert(addr & !0b111, true);
            self.shape_checker.handle_mem_event(addr, mw_record.prev_timestamp);
        }

        if let Some(record) = mw_record.prev_page_prot_record {
            self.shape_checker.handle_page_prot_event(record.page_idx, record.timestamp);
            self.touched_pages.insert(record.page_idx, true);
        }

        Ok(())
    }
}

impl<M: ExecutionMode> SplicingVM<'_, M> {
    /// Splice a minimal trace, outputting a minimal trace for the NEXT shard.
    pub fn splice<T: MinimalTrace>(&self, trace: T) -> Option<SplicedMinimalTrace<T>> {
        // If the trace has been exhausted, then the last splice is all thats needed.
        if self.core.is_trace_end() || self.core.is_done() {
            return None;
        }

        let total_mem_reads = trace.num_mem_reads();

        Some(SplicedMinimalTrace::new(
            trace,
            self.core.registers().iter().map(|v| v.value).collect::<Vec<_>>().try_into().unwrap(),
            self.core.pc(),
            self.core.clk(),
            total_mem_reads as usize - self.core.mem_reads.len(),
        ))
    }

    // Indicate that a new shard is starting.
    fn start_new_shard(&mut self) {
        self.shape_checker.reset(self.core.clk());
        self.core.register_refresh();
    }
}

impl<'a, M: ExecutionMode> SplicingVM<'a, M> {
    /// Create a new full-tracing VM from a minimal trace.
    pub fn new<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        touched_addresses: &'a mut CompressedMemory,
        touched_pages: &'a mut CompressedPages,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        opts: SP1CoreOpts,
    ) -> Self {
        let program_len = program.instructions.len() as u64;
        let ShardingThreshold { element_threshold, height_threshold } = opts.sharding_threshold;
        assert!(
            element_threshold >= HALT_AREA && height_threshold >= HALT_HEIGHT,
            "invalid sharding threshold"
        );

        Self {
            core: CoreVM::new(trace, program, opts, proof_nonce),
            touched_addresses,
            touched_pages,
            shape_checker: ShapeChecker::new(
                program_len,
                trace.clk_start(),
                ShardingThreshold {
                    element_threshold: element_threshold - HALT_AREA,
                    height_threshold: height_threshold - HALT_HEIGHT,
                },
            ),
            _mode: PhantomData,
        }
    }

    /// Handles recoverable errors such as traps.
    pub fn handle_error(&mut self, e: TrapError) -> Result<(), ExecutionError> {
        let TrapResult { context, code_record, pc_record, handler_record } =
            self.core.handle_error(e)?;

        self.touched_addresses.insert(context & !0b111, true);
        self.touched_addresses.insert((context + 8) & !0b111, true);
        self.touched_addresses.insert((context + 16) & !0b111, true);

        self.shape_checker.handle_mem_event(context, handler_record.prev_timestamp);
        self.shape_checker.handle_mem_event(context + 8, code_record.prev_timestamp);
        self.shape_checker.handle_mem_event(context + 16, pc_record.prev_timestamp);

        Ok(())
    }

    /// Execute an ALU instruction and emit the events.
    #[inline]
    pub fn execute_alu(&mut self, instruction: &Instruction) {
        let _ = self.core.execute_alu(instruction);
    }

    /// Execute a jump instruction and emit the events.
    #[inline]
    pub fn execute_jump(&mut self, instruction: &Instruction) {
        let _ = self.core.execute_jump(instruction);
    }

    /// Execute a branch instruction and emit the events.
    #[inline]
    pub fn execute_branch(&mut self, instruction: &Instruction) {
        let _ = self.core.execute_branch(instruction);
    }

    /// Execute a U-type instruction and emit the events.   
    #[inline]
    pub fn execute_utype(&mut self, instruction: &Instruction) {
        let _ = self.core.execute_utype(instruction);
    }

    /// Execute an ecall instruction and emit the events.
    #[inline]
    pub fn execute_ecall(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let code = self.core.read_code();

        if code.should_send() == 1 {
            if self.core.is_retained_syscall(code) {
                self.shape_checker.handle_retained_syscall(code);
            } else {
                self.shape_checker.syscall_sent();
            }
        }

        if code == SyscallCode::COMMIT || code == SyscallCode::COMMIT_DEFERRED_PROOFS {
            self.shape_checker.handle_commit();
        }

        let result = CoreVM::execute_ecall(self, instruction, code)?;

        let syscall_sent = self.shape_checker.get_syscall_sent();
        self.shape_checker.set_syscall_sent(false);

        if let Some(error) = result.error {
            self.handle_error(error)?;
        }

        if let Some(record) = result.sig_return_pc_record {
            self.shape_checker.handle_mem_event(result.b, record.prev_timestamp);
        }
        self.shape_checker.set_syscall_sent(syscall_sent);

        Ok(())
    }
}

impl<'a, M: ExecutionMode> SyscallRuntime<'a, M> for SplicingVM<'a, M> {
    const TRACING: bool = false;

    fn core(&self) -> &CoreVM<'a, M> {
        &self.core
    }

    fn core_mut(&mut self) -> &mut CoreVM<'a, M> {
        &mut self.core
    }

    fn rr(&mut self, register: usize) -> MemoryReadRecord {
        let record = SyscallRuntime::rr(self.core_mut(), register);
        self.shape_checker.local_mem_syscall_rr();
        record
    }

    fn rw(&mut self, register: usize, value: u64) -> MemoryWriteRecord {
        let record = SyscallRuntime::rw(self.core_mut(), register, value);
        self.shape_checker.local_mem_syscall_rr();
        record
    }

    fn page_prot_write(&mut self, page_idx: u64, prot: u8) -> PageProtRecord {
        let prev_page_prot_record = self.core_mut().page_prot_write(page_idx, prot);
        self.shape_checker.handle_page_prot_event(
            prev_page_prot_record.page_idx,
            prev_page_prot_record.timestamp,
        );
        self.touched_pages.insert(prev_page_prot_record.page_idx, true);
        prev_page_prot_record
    }

    fn page_prot_range_check(
        &mut self,
        start_page_idx: u64,
        end_page_idx: u64,
        page_prot_bitmap: u8,
    ) -> (Vec<PageProtRecord>, Option<TrapError>) {
        let (page_prot_records, error) =
            self.core_mut().page_prot_range_check(start_page_idx, end_page_idx, page_prot_bitmap);
        for record in page_prot_records.iter() {
            self.shape_checker.handle_page_prot_event(record.page_idx, record.timestamp);
            self.touched_pages.insert(record.page_idx, true);
        }
        (page_prot_records, error)
    }

    fn mr_without_prot(&mut self, addr: u64) -> MemoryReadRecord {
        let record = self.core_mut().mr_without_prot(addr);
        self.shape_checker.handle_mem_event(addr, record.prev_timestamp);
        record
    }

    fn mw_without_prot(&mut self, addr: u64) -> MemoryWriteRecord {
        let record = self.core_mut().mw_without_prot(addr);
        self.shape_checker.handle_mem_event(addr, record.prev_timestamp);
        record
    }

    fn mr_slice_without_prot(&mut self, addr: u64, len: usize) -> Vec<MemoryReadRecord> {
        let records = self.core_mut().mr_slice_without_prot(addr, len);
        for (i, record) in records.iter().enumerate() {
            self.shape_checker.handle_mem_event(addr + i as u64 * 8, record.prev_timestamp);
        }

        records
    }

    fn mw_slice_without_prot(&mut self, addr: u64, len: usize) -> Vec<MemoryWriteRecord> {
        let records = self.core_mut().mw_slice_without_prot(addr, len);
        for (i, record) in records.iter().enumerate() {
            self.shape_checker.handle_mem_event(addr + i as u64 * 8, record.prev_timestamp);
        }

        records
    }
}

/// A minimal trace implentation that starts at a different point in the trace,
/// but reuses the same memory reads and hint lens.
///
/// Note: This type implements [`Serialize`] but it is serialized as a [`TraceChunk`].
///
/// In order to deserialize this type, you must use the [`TraceChunk`] type.
#[derive(Debug, Clone)]
pub struct SplicedMinimalTrace<T: MinimalTrace> {
    inner: T,
    start_registers: [u64; 32],
    start_pc: u64,
    start_clk: u64,
    memory_reads_idx: usize,
    last_clk: u64,
    // Normally unused but can be set for the cluster.
    last_mem_reads_idx: usize,
}

impl<T: MinimalTrace> SplicedMinimalTrace<T> {
    /// Create a new spliced minimal trace.
    #[tracing::instrument(name = "SplicedMinimalTrace::new", skip(inner), level = "trace")]
    pub fn new(
        inner: T,
        start_registers: [u64; 32],
        start_pc: u64,
        start_clk: u64,
        memory_reads_idx: usize,
    ) -> Self {
        Self {
            inner,
            start_registers,
            start_pc,
            start_clk,
            memory_reads_idx,
            last_clk: 0,
            last_mem_reads_idx: 0,
        }
    }

    /// Create a new spliced minimal trace from a minimal trace without any splicing.
    #[tracing::instrument(
        name = "SplicedMinimalTrace::new_full_trace",
        skip(trace),
        level = "trace"
    )]
    pub fn new_full_trace(trace: T) -> Self {
        let start_registers = trace.start_registers();
        let start_pc = trace.pc_start();
        let start_clk = trace.clk_start();

        tracing::trace!("start_pc: {}", start_pc);
        tracing::trace!("start_clk: {}", start_clk);
        tracing::trace!("trace.num_mem_reads(): {}", trace.num_mem_reads());

        Self::new(trace, start_registers, start_pc, start_clk, 0)
    }

    /// Set the last clock of the spliced minimal trace.
    pub fn set_last_clk(&mut self, clk: u64) {
        self.last_clk = clk;
    }

    /// Set the last memory reads index of the spliced minimal trace.
    pub fn set_last_mem_reads_idx(&mut self, mem_reads_idx: usize) {
        self.last_mem_reads_idx = mem_reads_idx;
    }
}

impl<T: MinimalTrace> MinimalTrace for SplicedMinimalTrace<T> {
    fn start_registers(&self) -> [u64; 32] {
        self.start_registers
    }

    fn pc_start(&self) -> u64 {
        self.start_pc
    }

    fn clk_start(&self) -> u64 {
        self.start_clk
    }

    fn clk_end(&self) -> u64 {
        self.last_clk
    }

    fn num_mem_reads(&self) -> u64 {
        self.inner.num_mem_reads() - self.memory_reads_idx as u64
    }

    fn mem_reads(&self) -> MemReads<'_> {
        let mut reads = self.inner.mem_reads();
        reads.advance(self.memory_reads_idx);

        reads
    }
}

impl<T: MinimalTrace> Serialize for SplicedMinimalTrace<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let len = self.last_mem_reads_idx - self.memory_reads_idx;
        let mem_reads = unsafe {
            let mem_reads_buf = Arc::new_uninit_slice(len);
            let start_mem_reads = self.mem_reads();
            let src_ptr = start_mem_reads.head_raw();
            std::ptr::copy_nonoverlapping(src_ptr, mem_reads_buf.as_ptr() as *mut MemValue, len);
            mem_reads_buf.assume_init()
        };

        let trace = TraceChunk {
            start_registers: self.start_registers,
            pc_start: self.start_pc,
            clk_start: self.start_clk,
            clk_end: self.last_clk,
            mem_reads,
        };

        trace.serialize(serializer)
    }
}

/// Wrapper enum to handle `SplicingVM` with different execution modes at runtime.
pub enum SplicingVMEnum<'a> {
    /// `SplicingVM` for `SupervisorMode`.
    Supervisor(SplicingVM<'a, SupervisorMode>),
    /// `SplicingVM` for `UserMode`.
    User(SplicingVM<'a, UserMode>),
}

impl<'a> SplicingVMEnum<'a> {
    /// Create a new `SplicingVMEnum` based on program's `enable_untrusted_programs` flag.
    pub fn new<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        touched_addresses: &'a mut CompressedMemory,
        touched_pages: &'a mut CompressedPages,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        opts: SP1CoreOpts,
    ) -> Self {
        if program.enable_untrusted_programs {
            Self::User(SplicingVM::<UserMode>::new(
                trace,
                program,
                touched_addresses,
                touched_pages,
                proof_nonce,
                opts,
            ))
        } else {
            Self::Supervisor(SplicingVM::<SupervisorMode>::new(
                trace,
                program,
                touched_addresses,
                touched_pages,
                proof_nonce,
                opts,
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

    /// Splice a minimal trace, outputting a minimal trace for the NEXT shard.
    pub fn splice<T: MinimalTrace>(&self, trace: T) -> Option<SplicedMinimalTrace<T>> {
        match self {
            Self::Supervisor(vm) => vm.splice(trace),
            Self::User(vm) => vm.splice(trace),
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

    /// Get the global clock.
    #[must_use]
    pub fn global_clk(&self) -> u64 {
        match self {
            Self::Supervisor(vm) => vm.core.global_clk(),
            Self::User(vm) => vm.core.global_clk(),
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

    /// Get the number of remaining memory reads.
    #[must_use]
    pub fn mem_reads_len(&self) -> usize {
        match self {
            Self::Supervisor(vm) => vm.core.mem_reads.len(),
            Self::User(vm) => vm.core.mem_reads.len(),
        }
    }

    /// Get the registers.
    #[must_use]
    pub fn registers(&self) -> [MemoryRecord; 32] {
        match self {
            Self::Supervisor(vm) => *vm.core.registers(),
            Self::User(vm) => *vm.core.registers(),
        }
    }

    /// Get the exit code.
    #[must_use]
    pub fn exit_code(&self) -> u32 {
        match self {
            Self::Supervisor(vm) => vm.core.exit_code(),
            Self::User(vm) => vm.core.exit_code(),
        }
    }

    /// Check if done.
    #[must_use]
    pub fn is_done(&self) -> bool {
        match self {
            Self::Supervisor(vm) => vm.core.is_done(),
            Self::User(vm) => vm.core.is_done(),
        }
    }

    /// Get the public value digest.
    #[must_use]
    pub fn public_value_digest(&self) -> [u32; sp1_hypercube::air::PV_DIGEST_NUM_WORDS] {
        match self {
            Self::Supervisor(vm) => vm.core.public_value_digest,
            Self::User(vm) => vm.core.public_value_digest,
        }
    }

    /// Get the proof nonce.
    #[must_use]
    pub fn proof_nonce(&self) -> [u32; sp1_hypercube::air::PROOF_NONCE_NUM_WORDS] {
        match self {
            Self::Supervisor(vm) => vm.core.proof_nonce,
            Self::User(vm) => vm.core.proof_nonce,
        }
    }
}

#[cfg(test)]
mod tests {
    use sp1_jit::MemValue;

    use super::*;

    #[test]
    fn test_serialize_spliced_minimal_trace() {
        let trace_chunk = TraceChunk {
            start_registers: [1; 32],
            pc_start: 2,
            clk_start: 3,
            clk_end: 4,
            mem_reads: Arc::new([MemValue { clk: 8, value: 9 }, MemValue { clk: 10, value: 11 }]),
        };

        let mut trace = SplicedMinimalTrace::new(trace_chunk, [2; 32], 2, 3, 1);
        trace.set_last_mem_reads_idx(2);
        trace.set_last_clk(2);

        let serialized = bincode::serialize(&trace).unwrap();
        let deserialized: TraceChunk = bincode::deserialize(&serialized).unwrap();

        let expected = TraceChunk {
            start_registers: [2; 32],
            pc_start: 2,
            clk_start: 3,
            clk_end: 2,
            mem_reads: Arc::new([MemValue { clk: 10, value: 11 }]),
        };

        assert_eq!(deserialized, expected);
    }
}
