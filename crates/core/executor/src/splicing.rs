use std::sync::Arc;

use serde::Serialize;
use sp1_hypercube::air::PROOF_NONCE_NUM_WORDS;
use sp1_jit::{MemReads, MemValue, MinimalTrace, TraceChunk};

use crate::{
    events::{MemoryReadRecord, MemoryWriteRecord},
    vm::{
        memory::CompressedMemory,
        results::{CycleResult, LoadResult, StoreResult},
        shapes::ShapeChecker,
        syscall::SyscallRuntime,
        CoreVM,
    },
    ExecutionError, Instruction, Opcode, Program, SP1CoreOpts, SyscallCode,
};

/// A RISC-V VM that uses a [`MinimalTrace`] to create multiple [`SplicedMinimalTrace`]s.
///
/// These new [`SplicedMinimalTrace`]s correspond to exactly 1 execuction shard to be proved.
///
/// Note that this is the only time we account for trace area throught the execution pipeline.
pub struct SplicingVM<'a> {
    /// The core VM.
    pub core: CoreVM<'a>,
    /// The shape checker, responsible for cutting the execution when a shard limit is reached.
    pub shape_checker: ShapeChecker,
    /// The addresses that have been touched.
    pub touched_addresses: &'a mut CompressedMemory,
}

impl SplicingVM<'_> {
    /// Execute the program until it halts.
    pub fn execute(&mut self) -> Result<CycleResult, ExecutionError> {
        if self.core.is_done() {
            return Ok(CycleResult::Done(true));
        }

        loop {
            let mut result = self.execute_instruction()?;

            // If were not already done, ensure that we dont have a shard boundary.
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

        self.shape_checker.handle_instruction(
            &instruction,
            self.core.needs_bump_clk_high(),
            instruction.is_memory_load_instruction() && instruction.op_a == 0,
            self.core.needs_state_bump(&instruction),
        );

        Ok(self.core.advance())
    }

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

impl<'a> SplicingVM<'a> {
    /// Create a new full-tracing VM from a minimal trace.
    pub fn new<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        touched_addresses: &'a mut CompressedMemory,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        opts: SP1CoreOpts,
    ) -> Self {
        let program_len = program.instructions.len() as u64;
        let sharding_threshold = opts.sharding_threshold;
        Self {
            core: CoreVM::new(trace, program, opts, proof_nonce),
            touched_addresses,
            shape_checker: ShapeChecker::new(program_len, trace.clk_start(), sharding_threshold),
        }
    }

    /// Execute a load instruction.
    ///
    /// This method will update the local memory access for the memory read, the register read,
    /// and the register write.
    ///
    /// It will also emit the memory instruction event and the events for the load instruction.
    #[inline]
    pub fn execute_load(&mut self, instruction: &Instruction) -> Result<(), ExecutionError> {
        let LoadResult { addr, mr_record, .. } = self.core.execute_load(instruction)?;

        // Ensure the address is aligned to 8 bytes.
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
        let StoreResult { addr, mw_record, .. } = self.core.execute_store(instruction)?;

        // Ensure the address is aligned to 8 bytes.
        self.touched_addresses.insert(addr & !0b111, true);

        self.shape_checker.handle_mem_event(addr, mw_record.prev_timestamp);

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

        let _ = CoreVM::execute_ecall(self, instruction, code)?;

        Ok(())
    }
}

impl<'a> SyscallRuntime<'a> for SplicingVM<'a> {
    const TRACING: bool = false;

    fn core(&self) -> &CoreVM<'a> {
        &self.core
    }

    fn core_mut(&mut self) -> &mut CoreVM<'a> {
        &mut self.core
    }

    fn rr(&mut self, register: usize) -> MemoryReadRecord {
        let record = SyscallRuntime::rr(self.core_mut(), register);

        record
    }

    fn mw(&mut self, addr: u64) -> MemoryWriteRecord {
        let record = SyscallRuntime::mw(self.core_mut(), addr);

        self.shape_checker.handle_mem_event(addr, record.prev_timestamp);

        record
    }

    fn mr(&mut self, addr: u64) -> MemoryReadRecord {
        let record = SyscallRuntime::mr(self.core_mut(), addr);

        self.shape_checker.handle_mem_event(addr, record.prev_timestamp);

        record
    }

    fn mr_slice(&mut self, addr: u64, len: usize) -> Vec<MemoryReadRecord> {
        let records = SyscallRuntime::mr_slice(self.core_mut(), addr, len);

        for (i, record) in records.iter().enumerate() {
            self.shape_checker.handle_mem_event(addr + i as u64 * 8, record.prev_timestamp);
        }

        records
    }

    fn mw_slice(&mut self, addr: u64, len: usize) -> Vec<MemoryWriteRecord> {
        let records = SyscallRuntime::mw_slice(self.core_mut(), addr, len);

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
