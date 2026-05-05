use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use hashbrown::HashMap;
use sp1_hypercube::air::{PublicValues, PROOF_NONCE_NUM_WORDS};
use sp1_jit::MinimalTrace;
use sp1_primitives::consts::PAGE_SIZE;

use crate::{
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
    pub core: CoreVM<'a, M>,
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
    /// Phantom data for the execution mode.
    _mode: PhantomData<M>,
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
    fn execute_instruction(&mut self) -> Result<CycleResult, ExecutionError> {
        let pc = self.core.pc();
        let instruction = self.core.fetch();

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

        Ok(self.core.advance())
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
        let FetchResult { instruction, mr_record, pc, error } = self.core.fetch()?;

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
            return Ok(self.core.advance());
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

        Ok(self.core.advance())
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
    fn postprocess(&mut self) {
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

        Self {
            core: CoreVM::new(trace, program, opts, proof_nonce),
            record,
            local_memory_access: LocalMemoryAccess::default(),
            local_page_prot_access: LocalPageProtAccess::default(),
            precompile_local_memory_access: None,
            precompile_local_page_prot_access: None,
            decoded_instruction_events: HashMap::new(),
            _mode: PhantomData,
        }
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
            CoreVM::<'a>::execute_ecall(&mut PrecompileMemory::new(self), instruction, code)?;

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
        self.record.pc_start.get_or_insert(self.core.pc());
        self.record.next_pc = next_pc;
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

    fn core(&self) -> &CoreVM<'a, M> {
        &self.core
    }

    fn core_mut(&mut self) -> &mut CoreVM<'a, M> {
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

    fn core(&self) -> &CoreVM<'a, M> {
        self.inner.core()
    }

    fn core_mut(&mut self) -> &mut CoreVM<'a, M> {
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
