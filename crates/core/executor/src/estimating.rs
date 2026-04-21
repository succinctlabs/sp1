use sp1_hypercube::air::PROOF_NONCE_NUM_WORDS;
use sp1_jit::MinimalTrace;
use std::sync::Arc;

use crate::{
    events::{MemoryReadRecord, MemoryWriteRecord},
    vm::{
        gas::{ReportGenerator, ReportGeneratorSnapshot},
        results::{
            AluResult, BranchResult, CycleResult, JumpResult, LoadResult, MaybeImmediate,
            StoreResult, UTypeResult,
        },
        syscall::SyscallRuntime,
        CoreVM,
    },
    ExecutionError, ExecutionReport, Instruction, Opcode, Program, Register, SP1CoreOpts,
    SyscallCode,
};

/// A RISC-V VM that uses a [`MinimalTrace`] to create a [`ExecutionReport`].
pub struct GasEstimatingVM<'a> {
    /// The core VM.
    pub core: CoreVM<'a, ReportGeneratorSnapshot>,
    /// The gas calculator for the VM.
    pub gas_calculator: ReportGenerator,
    /// The index of the hint lens the next shard will use.
    pub hint_lens_idx: usize,
}

impl GasEstimatingVM<'_> {
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
    pub fn execute_instruction(&mut self) -> Result<CycleResult, ExecutionError> {
        let instruction = self.core.fetch(|| self.gas_calculator.snapshot());
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

        let (res, calls) = self.core.advance(|| self.gas_calculator.snapshot());

        if !calls.is_empty() {
            tracing::error!("Apc call application is not implemented for the `GasEstimatingVM`. Execution report will NOT take apcs into account");
        }

        Ok(res)
    }
}

impl<'a> GasEstimatingVM<'a> {
    /// Create a new gas estimating VM from a minimal trace.
    pub fn new<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        opts: SP1CoreOpts,
    ) -> Self {
        Self {
            core: CoreVM::new(trace, program, opts, proof_nonce),
            hint_lens_idx: 0,
            gas_calculator: ReportGenerator::new(trace.clk_start()),
        }
    }

    /// Execute a load instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the load instruction.
    pub fn execute_load(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let LoadResult { addr, rd, mr_record, rr_record, rw_record, rs1, .. } =
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
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the store instruction.
    pub fn execute_store(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let StoreResult { addr, mw_record, rs1_record, rs2_record, rs1, rs2, .. } =
            self.core.execute_store(instruction)?;

        self.gas_calculator.handle_instruction(
            instruction,
            self.core.needs_bump_clk_high(),
            false, // store instruction, no load of x0
            self.core.needs_state_bump(instruction),
        );

        self.gas_calculator.handle_mem_event(addr, mw_record.prev_timestamp);
        self.gas_calculator.handle_mem_event(rs1 as u64, rs1_record.prev_timestamp);
        self.gas_calculator.handle_mem_event(rs2 as u64, rs2_record.prev_timestamp);

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
            false, // alu instruction, no load of x0
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
            false, // jump instruction, no load of x0
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
            false, // branch instruction, no load of x0
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
            false, // u-type instruction, no load of x0
            self.core.needs_state_bump(instruction),
        );
    }

    /// Execute an ecall instruction and emit the events.
    #[inline]
    pub fn execute_ecall(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let code = self.core.read_code();

        let result = CoreVM::<ReportGeneratorSnapshot>::execute_ecall(self, instruction, code)?;

        if code == SyscallCode::HINT_LEN {
            self.hint_lens_idx += 1;
        }

        if code == SyscallCode::HALT {
            self.gas_calculator.set_exit_code(result.b);
        }

        if code.should_send() == 1 {
            if self.core.is_retained_syscall(code) {
                self.gas_calculator.handle_retained_syscall(code);
            } else {
                self.gas_calculator.syscall_sent(code);
            }
        }

        self.gas_calculator.handle_instruction(
            instruction,
            self.core.needs_bump_clk_high(),
            false, // ecall instruction, no load of x0
            self.core.needs_state_bump(instruction),
        );

        Ok(())
    }
}

impl<'a> SyscallRuntime<'a> for GasEstimatingVM<'a> {
    const TRACING: bool = false;
    type Snapshot = ReportGeneratorSnapshot;

    fn core(&self) -> &CoreVM<'a, Self::Snapshot> {
        &self.core
    }

    fn core_mut(&mut self) -> &mut CoreVM<'a, Self::Snapshot> {
        &mut self.core
    }

    fn mr(&mut self, addr: u64) -> MemoryReadRecord {
        let record = SyscallRuntime::mr(self.core_mut(), addr);

        self.gas_calculator.handle_mem_event(addr, record.prev_timestamp);

        record
    }

    fn mw_slice(&mut self, addr: u64, len: usize) -> Vec<MemoryWriteRecord> {
        let records = SyscallRuntime::mw_slice(self.core_mut(), addr, len);

        for (i, record) in records.iter().enumerate() {
            self.gas_calculator.handle_mem_event(addr + i as u64 * 8, record.prev_timestamp);
        }

        records
    }

    fn mr_slice(&mut self, addr: u64, len: usize) -> Vec<MemoryReadRecord> {
        let records = SyscallRuntime::mr_slice(self.core_mut(), addr, len);

        for (i, record) in records.iter().enumerate() {
            self.gas_calculator.handle_mem_event(addr + i as u64 * 8, record.prev_timestamp);
        }

        records
    }

    fn rr(&mut self, register: usize) -> MemoryReadRecord {
        let record = SyscallRuntime::rr(self.core_mut(), register);

        self.gas_calculator.handle_mem_event(register as u64, record.prev_timestamp);

        record
    }

    fn mw(&mut self, addr: u64) -> MemoryWriteRecord {
        let record = SyscallRuntime::mw(self.core_mut(), addr);

        self.gas_calculator.handle_mem_event(addr, record.prev_timestamp);

        record
    }
}
