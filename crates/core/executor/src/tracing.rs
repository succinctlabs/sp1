use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use hashbrown::HashMap;
use sp1_hypercube::air::{PublicValues, PROOF_NONCE_NUM_WORDS};
use sp1_jit::MinimalTrace;

use crate::{
    autoprecompiles::ExecutionRecordSnapshotWithPc,
    events::{
        AluEvent, BranchEvent, IntoMemoryRecord, JumpEvent, MemInstrEvent, MemoryLocalEvent,
        MemoryReadRecord, MemoryRecord, MemoryRecordEnum, MemoryWriteRecord, PrecompileEvent,
        SyscallEvent, UTypeEvent,
    },
    vm::{
        results::{
            AluResult, BranchResult, CycleResult, EcallResult, JumpResult, LoadResult,
            MaybeImmediate, StoreResult, UTypeResult,
        },
        syscall::SyscallRuntime,
        CoreVM,
    },
    ALUTypeRecord, ExecutionError, ExecutionRecord, ITypeRecord, Instruction, JTypeRecord,
    MemoryAccessRecord, Opcode, Program, RTypeRecord, Register, SP1CoreOpts, SyscallCode,
};

/// A RISC-V VM that uses a [`MinimalTrace`] to create a [`ExecutionRecord`].
pub struct TracingVM<'a> {
    /// The core VM.
    pub core: CoreVM<'a, ExecutionRecordSnapshotWithPc>,
    /// The local memory access for the CPU.
    pub local_memory_access: LocalMemoryAccess,
    /// The local memory access for any deferred precompiles.
    pub precompile_local_memory_access: Option<LocalMemoryAccess>,
    /// The execution record were populating.
    pub record: &'a mut ExecutionRecord,
}

impl TracingVM<'_> {
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
        // TODO: is there a way to avoid this call? It is needed now so that `next_pc` is set correctly in the apc record
        let pc = self.core.pc();
        let instruction = self
            .core
            .fetch(|| ExecutionRecordSnapshotWithPc { record: self.record.snapshot(), pc });
        if instruction.is_none() {
            unreachable!("Fetching the next instruction failed");
        }

        // SAFETY: The instruction is guaranteed to be valid as we checked for `is_none` above.
        let instruction = unsafe { *instruction.unwrap_unchecked() };

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

        self.core.check_bump(&instruction);

        let next_pc = self.core.next_pc();
        let (res, calls) = self.core.advance(|| ExecutionRecordSnapshotWithPc {
            record: self.record.snapshot(),
            pc: next_pc,
        });
        self.record.apply_calls(&calls);

        Ok(res)
    }

    fn postprocess(&mut self) {
        if self.record.last_timestamp == 0 {
            self.record.last_timestamp = self.core.clk();
        }

        self.record.program = self.core.program.clone();
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

impl<'a> TracingVM<'a> {
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
            precompile_local_memory_access: None,
        }
    }

    /// Get the public values from the record.
    #[must_use]
    pub fn public_values(&self) -> &PublicValues<u32, u64, u64, u32> {
        &self.record.public_values
    }

    /// Execute a load instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the load instruction.
    pub fn execute_load(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let LoadResult { mut a, b, c, rs1, rd, addr, rr_record, rw_record, mr_record } =
            self.core.execute_load(instruction)?;

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(rw_record)),
            b: Some(MemoryRecordEnum::Read(rr_record)),
            c: None,
            memory: Some(MemoryRecordEnum::Read(mr_record)),
            untrusted_instruction: None,
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.local_memory_access.insert_record(rd as u64, rw_record);
        self.local_memory_access.insert_record(rs1 as u64, rr_record);
        self.local_memory_access.insert_record(addr & !0b111, mr_record);

        self.emit_events(self.core.clk(), self.core.next_pc(), instruction, &mem_access_record, 0);
        self.emit_mem_instr_event(instruction, a, b, c, &mem_access_record, op_a_0);

        Ok(())
    }

    /// Execute a store instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the store instruction.
    fn execute_store(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let StoreResult { mut a, b, c, rs1, rs2, addr, rs1_record, rs2_record, mw_record } =
            self.core.execute_store(instruction)?;

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Read(rs1_record)),
            b: Some(MemoryRecordEnum::Read(rs2_record)),
            c: None,
            memory: Some(MemoryRecordEnum::Write(mw_record)),
            untrusted_instruction: None,
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.local_memory_access.insert_record(addr & !0b111, mw_record);
        self.local_memory_access.insert_record(rs1 as u64, rs1_record);
        self.local_memory_access.insert_record(rs2 as u64, rs2_record);

        self.emit_mem_instr_event(instruction, a, b, c, &mem_access_record, op_a_0);
        self.emit_events(self.core.clk(), self.core.next_pc(), instruction, &mem_access_record, 0);

        Ok(())
    }

    /// Execute an ALU instruction and emit the events.
    fn execute_alu(&mut self, instruction: &Instruction) {
        let AluResult { rd, rw_record, mut a, b, c, rs1, rs2 } = self.core.execute_alu(instruction);

        if let MaybeImmediate::Register(rs2, rs2_record) = rs2 {
            self.local_memory_access.insert_record(rs2 as u64, rs2_record);
        }

        if let MaybeImmediate::Register(rs1, rs1_record) = rs1 {
            self.local_memory_access.insert_record(rs1 as u64, rs1_record);
        }

        self.local_memory_access.insert_record(rd as u64, rw_record);

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(rw_record)),
            b: rs1.record().map(|r| MemoryRecordEnum::Read(*r)),
            c: rs2.record().map(|r| MemoryRecordEnum::Read(*r)),
            memory: None,
            untrusted_instruction: None,
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.emit_events(self.core.clk(), self.core.next_pc(), instruction, &mem_access_record, 0);
        self.emit_alu_event(instruction, a, b, c, &mem_access_record, op_a_0);
    }

    /// Execute a jump instruction and emit the events.
    fn execute_jump(&mut self, instruction: &Instruction) {
        let JumpResult { mut a, b, c, rd, rd_record, rs1 } = self.core.execute_jump(instruction);

        if let MaybeImmediate::Register(rs1, rs1_record) = rs1 {
            self.local_memory_access.insert_record(rs1 as u64, rs1_record);
        }

        self.local_memory_access.insert_record(rd as u64, rd_record);

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(rd_record)),
            b: rs1.record().map(|r| MemoryRecordEnum::Read(*r)),
            c: None,
            memory: None,
            untrusted_instruction: None,
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.emit_events(self.core.clk(), self.core.next_pc(), instruction, &mem_access_record, 0);
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
    fn execute_branch(&mut self, instruction: &Instruction) {
        let BranchResult { mut a, rs1, a_record, b, rs2, b_record, c } =
            self.core.execute_branch(instruction);

        self.local_memory_access.insert_record(rs2 as u64, b_record);
        self.local_memory_access.insert_record(rs1 as u64, a_record);

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Read(a_record)),
            b: Some(MemoryRecordEnum::Read(b_record)),
            c: None,
            memory: None,
            untrusted_instruction: None,
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.emit_events(self.core.clk(), self.core.next_pc(), instruction, &mem_access_record, 0);
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
    fn execute_utype(&mut self, instruction: &Instruction) {
        let UTypeResult { mut a, b, c, rd, rw_record } = self.core.execute_utype(instruction);

        self.local_memory_access.insert_record(rd as u64, rw_record);

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(rw_record)),
            b: None,
            c: None,
            memory: None,
            untrusted_instruction: None,
        };

        let op_a_0 = instruction.op_a == 0;
        if op_a_0 {
            a = 0;
        }

        self.emit_events(self.core.clk(), self.core.next_pc(), instruction, &mem_access_record, 0);
        self.emit_utype_event(instruction, a, b, c, &mem_access_record, op_a_0);
    }

    /// Execute an ecall instruction and emit the events.
    fn execute_ecall(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let code = self.core.read_code();

        // If the syscall is not retained, we need to track the local memory access separately.
        //
        // Note that the `precompile_local_memory_access` is set to `None` in the
        // `postprocess_precompile` method.
        if !self.core().is_retained_syscall(code) && code.should_send() == 1 {
            self.precompile_local_memory_access = Some(LocalMemoryAccess::default());
        }

        // Actually execute the ecall.
        let EcallResult { a: _, a_record, b, b_record, c, c_record } =
            CoreVM::<'a, ExecutionRecordSnapshotWithPc>::execute_ecall(self, instruction, code)?;

        self.local_memory_access.insert_record(Register::X11 as u64, c_record);
        self.local_memory_access.insert_record(Register::X10 as u64, b_record);
        self.local_memory_access.insert_record(Register::X5 as u64, a_record);

        let mem_access_record = MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(a_record)),
            b: Some(MemoryRecordEnum::Read(b_record)),
            c: Some(MemoryRecordEnum::Read(c_record)),
            memory: None,
            untrusted_instruction: None,
        };

        let op_a_0 = instruction.op_a == 0;
        self.emit_events(
            self.core.clk(),
            self.core.next_pc(),
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
            op_a_0,
            self.core.next_pc(),
            self.core.exit_code(),
            instruction,
        );

        Ok(())
    }
}

impl TracingVM<'_> {
    /// Emit events for this cycle.
    #[allow(clippy::too_many_arguments)]
    fn emit_events(
        &mut self,
        clk: u64,
        next_pc: u64,
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
    }

    /// Emit a memory instruction event.
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
        op_a_0: bool,
        next_pc: u64,
        exit_code: u32,
        instruction: &Instruction,
    ) {
        let syscall_event =
            self.syscall_event(clk, syscall_code, arg1, arg2, op_a_0, next_pc, exit_code);

        let record = RTypeRecord::new(record, instruction);
        self.record.syscall_events.push((syscall_event, record));
    }
}

impl<'a> SyscallRuntime<'a> for TracingVM<'a> {
    const TRACING: bool = true;
    type Snapshot = ExecutionRecordSnapshotWithPc;

    fn core(&self) -> &CoreVM<'a, Self::Snapshot> {
        &self.core
    }

    fn core_mut(&mut self) -> &mut CoreVM<'a, Self::Snapshot> {
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
        op_a_0: bool,
        next_pc: u64,
        exit_code: u32,
    ) -> SyscallEvent {
        // should_send: if the syscall is usually sent and it is not manually set as internal.
        let should_send =
            syscall_code.should_send() != 0 && !self.core.is_retained_syscall(syscall_code);

        SyscallEvent {
            pc: self.core.pc(),
            next_pc,
            clk,
            op_a_0,
            should_send,
            syscall_code,
            syscall_id: syscall_code.syscall_id(),
            arg1,
            arg2,
            exit_code,
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

    fn mr(&mut self, addr: u64) -> MemoryReadRecord {
        let record = SyscallRuntime::mr(self.core_mut(), addr);

        if let Some(local_memory_access) = &mut self.precompile_local_memory_access {
            local_memory_access.insert_record(addr, record);
        } else {
            self.local_memory_access.insert_record(addr, record);
        }

        record
    }

    fn mr_slice(&mut self, addr: u64, len: usize) -> Vec<MemoryReadRecord> {
        let records = SyscallRuntime::mr_slice(self.core_mut(), addr, len);

        for (i, record) in records.iter().enumerate() {
            if let Some(local_memory_access) = &mut self.precompile_local_memory_access {
                local_memory_access.insert_record(addr + i as u64 * 8, *record);
            } else {
                self.local_memory_access.insert_record(addr + i as u64 * 8, *record);
            }
        }

        records
    }

    fn mw(&mut self, addr: u64) -> MemoryWriteRecord {
        let record = SyscallRuntime::mw(self.core_mut(), addr);

        if let Some(local_memory_access) = &mut self.precompile_local_memory_access {
            local_memory_access.insert_record(addr, record);
        } else {
            self.local_memory_access.insert_record(addr, record);
        }

        record
    }

    fn mw_slice(&mut self, addr: u64, len: usize) -> Vec<MemoryWriteRecord> {
        let records = SyscallRuntime::mw_slice(self.core_mut(), addr, len);

        for (i, record) in records.iter().enumerate() {
            if let Some(local_memory_access) = &mut self.precompile_local_memory_access {
                local_memory_access.insert_record(addr + i as u64 * 8, *record);
            } else {
                self.local_memory_access.insert_record(addr + i as u64 * 8, *record);
            }
        }

        records
    }

    fn postprocess_precompile(&mut self) -> Vec<MemoryLocalEvent> {
        let mut precompile_local_memory_access = Vec::new();

        if let Some(mut local_memory_access) =
            std::mem::take(&mut self.precompile_local_memory_access)
        {
            for (addr, event) in local_memory_access.drain() {
                if let Some(cpu_mem_access) = self.local_memory_access.remove(&addr) {
                    self.record.cpu_local_memory_access.push(cpu_mem_access);
                }

                precompile_local_memory_access.push(event);
            }
        }

        precompile_local_memory_access
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use powdr_autoprecompiles::execution::{
        OptimisticConstraint, OptimisticConstraints, OptimisticExpression, OptimisticLiteral,
    };

    use crate::{
        utils::add_halt, Apc, CycleResult, ExecutionRecord, Instruction, MinimalExecutor, Opcode,
        Program, Register, SP1Context, SP1CoreOpts, TracingVM,
    };

    fn run_tracing_vm(
        program: Arc<Program>,
        opts: SP1CoreOpts,
        max_trace_size: u64,
    ) -> (ExecutionRecord, [crate::events::MemoryRecord; 32], CycleResult) {
        let mut minimal = MinimalExecutor::tracing(program.clone(), max_trace_size);
        let chunk = minimal.execute_chunk().expect("trace chunk");

        let proof_nonce = SP1Context::default().proof_nonce;
        let mut record =
            ExecutionRecord::new(program.clone(), proof_nonce, opts.global_dependencies_opt);
        let mut vm = TracingVM::new(&chunk, program, opts, proof_nonce, &mut record);
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
            assert_eq!(!record.apc_events.is_empty(), should_execute_apcs);
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
        assert_eq!(record.apc_events.len(), 2);
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
            assert!(record.apc_events.is_empty());
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
            assert_eq!(record.apc_events.len(), 1);
            assert_eq!(record.apc_events.get_events(0).unwrap().count, 1);
            assert!(record.apc_events.get_events(1).is_none());
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
        assert_eq!(record.apc_events.len(), 2);
        assert!(record.apc_events.get_events(0).is_none());
        assert_eq!(record.apc_events.get_events(1).unwrap().count, 1);
        assert_eq!(record.apc_events.get_events(2).unwrap().count, 1);
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
        assert_eq!(record.apc_events.len(), 1);
        assert_eq!(record.apc_events.get_events(0).unwrap().count, 1);
        assert!(record.apc_events.get_events(1).is_none());
        assert!(record.apc_events.get_events(2).is_none());
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
            record.apc_events.is_empty(),
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
            record.apc_events.is_empty(),
            "Expected APC to be rejected due to memory bump (stale register access across epoch)"
        );
    }
}
