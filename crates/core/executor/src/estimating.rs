use sp1_hypercube::air::PROOF_NONCE_NUM_WORDS;
use sp1_jit::MinimalTrace;
use sp1_primitives::consts::LOG_PAGE_SIZE;
use std::{marker::PhantomData, sync::Arc};

use crate::{
    events::{MemoryReadRecord, MemoryRecord, MemoryWriteRecord, PageProtRecord},
    vm::{
        gas::ReportGenerator,
        results::{
            AluResult, BranchResult, CycleResult, FetchResult, JumpResult, LoadResult,
            LoadResultSupervisor, MaybeImmediate, StoreResult, StoreResultSupervisor, TrapResult,
            UTypeResult,
        },
        syscall::SyscallRuntime,
        CoreVM,
    },
    ExecutionError, ExecutionMode, ExecutionReport, Instruction, Opcode, Program, Register,
    SP1CoreOpts, SupervisorMode, SyscallCode, TrapError, UserMode,
};

/// A RISC-V VM that uses a [`MinimalTrace`] to create a [`ExecutionReport`].
///
/// The type parameter `M` determines whether page protection checks are enabled.
pub struct GasEstimatingVM<'a, M: ExecutionMode> {
    /// The core VM.
    pub core: CoreVM<'a, M>,
    /// The gas calculator for the VM.
    pub gas_calculator: ReportGenerator,
    /// The index of the hint lens the next shard will use.
    pub hint_lens_idx: usize,
    /// Phantom data for the execution mode.
    _mode: PhantomData<M>,
}

impl GasEstimatingVM<'_, SupervisorMode> {
    /// Execute the program until it halts.
    pub fn execute(&mut self) -> Result<ExecutionReport, ExecutionError> {
        if self.core.is_done() {
            return Ok(self.gas_calculator.generate_report());
        }

        loop {
            match self.execute_instruction()? {
                CycleResult::Done(false) => {}
                CycleResult::TraceEnd | CycleResult::ShardBoundary | CycleResult::Done(true) => {
                    return Ok(self.gas_calculator.generate_report());
                }
            }
        }
    }

    /// Execute the next instruction at the current PC.
    fn execute_instruction(&mut self) -> Result<CycleResult, ExecutionError> {
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

        Ok(self.core.advance())
    }
}

impl GasEstimatingVM<'_, SupervisorMode> {
    /// Execute a load instruction.
    pub fn execute_load(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let LoadResultSupervisor { addr, rd, mr_record, rr_record, rw_record, rs1, .. } =
            self.core.execute_load(instruction)?;

        self.gas_calculator.handle_instruction(
            instruction,
            self.core.needs_bump_clk_high(),
            rd == Register::X0,
            self.core.needs_state_bump(instruction),
        );

        self.gas_calculator.handle_mem_event(addr, mr_record.prev_timestamp);
        self.gas_calculator.handle_mem_event(rs1 as u64, rr_record.prev_timestamp);
        self.gas_calculator.handle_mem_event(rd as u64, rw_record.prev_timestamp);

        Ok(())
    }

    /// Execute a store instruction.
    pub fn execute_store(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let StoreResultSupervisor { addr, mw_record, rs1_record, rs2_record, rs1, rs2, .. } =
            self.core.execute_store(instruction)?;

        self.gas_calculator.handle_instruction(
            instruction,
            self.core.needs_bump_clk_high(),
            false,
            self.core.needs_state_bump(instruction),
        );

        self.gas_calculator.handle_mem_event(addr, mw_record.prev_timestamp);
        self.gas_calculator.handle_mem_event(rs1 as u64, rs1_record.prev_timestamp);
        self.gas_calculator.handle_mem_event(rs2 as u64, rs2_record.prev_timestamp);

        Ok(())
    }
}

impl GasEstimatingVM<'_, UserMode> {
    /// Execute the program until it halts.
    pub fn execute(&mut self) -> Result<ExecutionReport, ExecutionError> {
        if self.core.is_done() {
            return Ok(self.gas_calculator.generate_report());
        }

        loop {
            match self.execute_instruction()? {
                CycleResult::Done(false) => {}
                CycleResult::TraceEnd | CycleResult::ShardBoundary | CycleResult::Done(true) => {
                    return Ok(self.gas_calculator.generate_report());
                }
            }
        }
    }

    /// Execute the next instruction at the current PC.
    fn execute_instruction(&mut self) -> Result<CycleResult, ExecutionError> {
        let FetchResult { instruction, mr_record, pc, error } = self.core.fetch()?;

        if let Some(error) = error {
            self.handle_error(error)?;
            self.gas_calculator.handle_page_prot_event(
                pc >> LOG_PAGE_SIZE,
                mr_record.unwrap().prev_page_prot_record.unwrap().timestamp,
            );
            self.gas_calculator.handle_page_prot_check();
            self.gas_calculator.handle_trap_exec_event();
            self.gas_calculator.handle_trap_events(self.core.needs_bump_clk_high());
            self.gas_calculator.update_page_chip_counts();
            return Ok(self.core.advance());
        }

        if instruction.is_none() {
            unreachable!("Fetching the next instruction failed");
        }

        if let Some(mr_record) = mr_record {
            self.gas_calculator.handle_untrusted_instruction();
            self.gas_calculator.handle_mem_event(pc & !0b111, mr_record.prev_timestamp);
            self.gas_calculator.handle_page_prot_event(
                pc >> LOG_PAGE_SIZE,
                mr_record.prev_page_prot_record.unwrap().timestamp,
            );
            self.gas_calculator.handle_page_prot_check();
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

        self.gas_calculator.update_page_chip_counts();
        Ok(self.core.advance())
    }
}

impl GasEstimatingVM<'_, UserMode> {
    /// Execute a load instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the load instruction.
    pub fn execute_load(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let LoadResult { addr, rd, mr_record, error, rr_record, rw_record, rs1, .. } =
            self.core.execute_load(instruction)?;

        if let Some(error) = error {
            self.handle_error(error)?;
            self.gas_calculator.handle_trap_mem_event();
        } else {
            self.gas_calculator.handle_mem_event(addr, mr_record.prev_timestamp);
        }

        if let Some(record) = mr_record.prev_page_prot_record {
            self.gas_calculator.handle_page_prot_event(record.page_idx, record.timestamp);
            self.gas_calculator.handle_page_prot_check();
        }

        self.gas_calculator.handle_mem_event(rs1 as u64, rr_record.prev_timestamp);
        self.gas_calculator.handle_mem_event(rd as u64, rw_record.prev_timestamp);

        self.gas_calculator.handle_instruction(
            instruction,
            self.core.needs_bump_clk_high(),
            rd == Register::X0,
            self.core.needs_state_bump(instruction),
        );

        Ok(())
    }

    /// Execute a store instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the store instruction.
    pub fn execute_store(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let StoreResult { addr, mw_record, error, rs1_record, rs2_record, rs1, rs2, .. } =
            self.core.execute_store(instruction)?;

        if let Some(error) = error {
            self.handle_error(error)?;
            self.gas_calculator.handle_trap_mem_event();
        } else {
            self.gas_calculator.handle_mem_event(addr, mw_record.prev_timestamp);
        }

        if let Some(record) = mw_record.prev_page_prot_record {
            self.gas_calculator.handle_page_prot_event(record.page_idx, record.timestamp);
            self.gas_calculator.handle_page_prot_check();
        }

        self.gas_calculator.handle_mem_event(rs1 as u64, rs1_record.prev_timestamp);
        self.gas_calculator.handle_mem_event(rs2 as u64, rs2_record.prev_timestamp);

        self.gas_calculator.handle_instruction(
            instruction,
            self.core.needs_bump_clk_high(),
            false,
            self.core.needs_state_bump(instruction),
        );

        Ok(())
    }
}

impl<'a, M: ExecutionMode> GasEstimatingVM<'a, M> {
    /// Create a new gas estimating VM from a minimal trace.
    pub fn new<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        opts: SP1CoreOpts,
    ) -> Self {
        let enable_untrusted_programs = program.enable_untrusted_programs;
        Self {
            core: CoreVM::new(trace, program, opts, proof_nonce),
            gas_calculator: ReportGenerator::new(trace.clk_start(), enable_untrusted_programs),
            hint_lens_idx: 0,
            _mode: PhantomData,
        }
    }

    /// Handles recoverable errors such as traps.
    pub fn handle_error(&mut self, e: TrapError) -> Result<(), ExecutionError> {
        let TrapResult { context, code_record, pc_record, handler_record } =
            self.core.handle_error(e)?;

        self.gas_calculator.handle_mem_event(context, handler_record.prev_timestamp);
        self.gas_calculator.handle_mem_event(context + 8, code_record.prev_timestamp);
        self.gas_calculator.handle_mem_event(context + 16, pc_record.prev_timestamp);

        Ok(())
    }

    /// Execute an ALU instruction and emit the events.
    #[inline]
    pub fn execute_alu(&mut self, instruction: &Instruction) {
        let AluResult { rd, rw_record, rs1, rs2, .. } = self.core.execute_alu(instruction);

        self.gas_calculator.handle_mem_event(rd as u64, rw_record.prev_timestamp);

        if let MaybeImmediate::Register(register, record) = rs1 {
            self.gas_calculator.handle_mem_event(register as u64, record.prev_timestamp);
        }

        if let MaybeImmediate::Register(register, record) = rs2 {
            self.gas_calculator.handle_mem_event(register as u64, record.prev_timestamp);
        }

        self.gas_calculator.handle_instruction(
            instruction,
            self.core.needs_bump_clk_high(),
            false,
            self.core.needs_state_bump(instruction),
        );
    }

    /// Execute a jump instruction and emit the events.
    #[inline]
    pub fn execute_jump(&mut self, instruction: &Instruction) {
        let JumpResult { rd, rd_record, rs1, .. } = self.core.execute_jump(instruction);

        self.gas_calculator.handle_mem_event(rd as u64, rd_record.prev_timestamp);

        if let MaybeImmediate::Register(register, record) = rs1 {
            self.gas_calculator.handle_mem_event(register as u64, record.prev_timestamp);
        }

        self.gas_calculator.handle_instruction(
            instruction,
            self.core.needs_bump_clk_high(),
            false,
            self.core.needs_state_bump(instruction),
        );
    }

    /// Execute a branch instruction and emit the events.
    #[inline]
    pub fn execute_branch(&mut self, instruction: &Instruction) {
        let BranchResult { rs1, a_record, rs2, b_record, .. } =
            self.core.execute_branch(instruction);

        self.gas_calculator.handle_mem_event(rs1 as u64, a_record.prev_timestamp);
        self.gas_calculator.handle_mem_event(rs2 as u64, b_record.prev_timestamp);

        self.gas_calculator.handle_instruction(
            instruction,
            self.core.needs_bump_clk_high(),
            false,
            self.core.needs_state_bump(instruction),
        );
    }

    /// Execute a U-type instruction and emit the events.
    #[inline]
    pub fn execute_utype(&mut self, instruction: &Instruction) {
        let UTypeResult { rd, rw_record, .. } = self.core.execute_utype(instruction);

        self.gas_calculator.handle_mem_event(rd as u64, rw_record.prev_timestamp);

        self.gas_calculator.handle_instruction(
            instruction,
            self.core.needs_bump_clk_high(),
            false,
            self.core.needs_state_bump(instruction),
        );
    }

    /// Execute an ecall instruction and emit the events.
    #[inline]
    pub fn execute_ecall(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let code = self.core.read_code();

        if code.should_send() == 1 {
            if self.core.is_retained_syscall(code) {
                self.gas_calculator.handle_retained_syscall(code);
            } else {
                self.gas_calculator.syscall_sent(code);
            }
        }

        if code == SyscallCode::HINT_LEN {
            self.hint_lens_idx += 1;
        }

        let result = CoreVM::execute_ecall(self, instruction, code)?;

        let syscall_sent = self.gas_calculator.get_syscall_sent();
        self.gas_calculator.set_syscall_sent(false);

        if let Some(error) = result.error {
            self.handle_error(error)?;
        }

        if let Some(record) = result.sig_return_pc_record {
            self.gas_calculator.handle_mem_event(result.b, record.prev_timestamp);
        }
        self.gas_calculator.set_syscall_sent(syscall_sent);

        if code == SyscallCode::HALT {
            self.gas_calculator.set_exit_code(result.b);
        }

        self.gas_calculator.handle_instruction(
            instruction,
            self.core.needs_bump_clk_high(),
            false,
            self.core.needs_state_bump(instruction),
        );

        Ok(())
    }
}

impl<'a, M: ExecutionMode> SyscallRuntime<'a, M> for GasEstimatingVM<'a, M> {
    const TRACING: bool = false;

    fn core(&self) -> &CoreVM<'a, M> {
        &self.core
    }

    fn core_mut(&mut self) -> &mut CoreVM<'a, M> {
        &mut self.core
    }

    fn rr(&mut self, register: usize) -> MemoryReadRecord {
        let record = SyscallRuntime::rr(self.core_mut(), register);

        self.gas_calculator.local_mem_syscall_rr();

        record
    }

    fn rw(&mut self, register: usize, value: u64) -> MemoryWriteRecord {
        let record = SyscallRuntime::rw(self.core_mut(), register, value);
        self.gas_calculator.local_mem_syscall_rr();
        record
    }

    fn page_prot_write(&mut self, page_idx: u64, prot: u8) -> PageProtRecord {
        let prev_page_prot_record = self.core_mut().page_prot_write(page_idx, prot);
        self.gas_calculator.handle_page_prot_event(
            prev_page_prot_record.page_idx,
            prev_page_prot_record.timestamp,
        );
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
            self.gas_calculator.handle_page_prot_event(record.page_idx, record.timestamp);
        }
        (page_prot_records, error)
    }

    fn mr_without_prot(&mut self, addr: u64) -> MemoryReadRecord {
        let record = self.core_mut().mr_without_prot(addr);
        self.gas_calculator.handle_mem_event(addr, record.prev_timestamp);
        record
    }

    fn mw_without_prot(&mut self, addr: u64) -> MemoryWriteRecord {
        let record = self.core_mut().mw_without_prot(addr);
        self.gas_calculator.handle_mem_event(addr, record.prev_timestamp);
        record
    }

    fn mr_slice_without_prot(&mut self, addr: u64, len: usize) -> Vec<MemoryReadRecord> {
        let records = self.core_mut().mr_slice_without_prot(addr, len);
        for (i, record) in records.iter().enumerate() {
            self.gas_calculator.handle_mem_event(addr + i as u64 * 8, record.prev_timestamp);
        }

        records
    }

    fn mw_slice_without_prot(&mut self, addr: u64, len: usize) -> Vec<MemoryWriteRecord> {
        let records = self.core_mut().mw_slice_without_prot(addr, len);
        for (i, record) in records.iter().enumerate() {
            self.gas_calculator.handle_mem_event(addr + i as u64 * 8, record.prev_timestamp);
        }

        records
    }
}

/// Wrapper enum to handle `GasEstimatingVM` with different execution modes at runtime.
pub enum GasEstimatingVMEnum<'a> {
    /// `GasEstimatingVM` for `SupervisorMode`.
    Supervisor(GasEstimatingVM<'a, SupervisorMode>),
    /// `GasEstimatingVM` for `UserMode`.
    User(GasEstimatingVM<'a, UserMode>),
}

impl<'a> GasEstimatingVMEnum<'a> {
    /// Create a new `GasEstimatingVMEnum` based on program's `enable_untrusted_programs` flag.
    pub fn new<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        opts: SP1CoreOpts,
    ) -> Self {
        if program.enable_untrusted_programs {
            Self::User(GasEstimatingVM::<UserMode>::new(trace, program, proof_nonce, opts))
        } else {
            Self::Supervisor(GasEstimatingVM::<SupervisorMode>::new(
                trace,
                program,
                proof_nonce,
                opts,
            ))
        }
    }

    /// Execute the program until it halts.
    pub fn execute(&mut self) -> Result<ExecutionReport, ExecutionError> {
        match self {
            Self::Supervisor(vm) => vm.execute(),
            Self::User(vm) => vm.execute(),
        }
    }

    /// Check if the VM has completed execution.
    #[must_use]
    pub fn is_done(&self) -> bool {
        match self {
            Self::Supervisor(vm) => vm.core.is_done(),
            Self::User(vm) => vm.core.is_done(),
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

    /// Get the current clock.
    #[must_use]
    pub fn clk(&self) -> u64 {
        match self {
            Self::Supervisor(vm) => vm.core.clk(),
            Self::User(vm) => vm.core.clk(),
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
