use crate::{memory::MAX_LOG_ADDR, Instruction, Opcode, Program, Register, HALT_PC};
use sp1_jit::{
    debug, DebugBackend, JitFunction, MemValue, MemoryView, RiscOperand, RiscRegister,
    RiscvTranspiler, TraceChunkRaw, TranspilerBackend,
};
use std::{
    collections::VecDeque,
    ptr::NonNull,
    sync::{mpsc, Arc},
};

#[cfg(test)]
mod tests;

/// A minimal trace executor.
pub struct MinimalExecutor {
    program: Arc<Program>,
    compiled: JitFunction,
    input: VecDeque<Vec<u8>>,
}

impl MinimalExecutor {
    /// Create a new minimal executor and transpile the program.
    ///
    /// # Arguments
    ///
    /// * `program` - The program to execute.
    /// * `is_debug` - Whether to compile the program with debugging.
    /// * `max_trace_size` - The maximum trace size in terms of [`MemValue`]s. If not set tracing
    ///   will be disabled.
    #[must_use]
    pub fn new(program: Arc<Program>, is_debug: bool, max_trace_size: Option<u64>) -> Self {
        tracing::debug!("transpiling program, debug={is_debug}, max_trace_size={max_trace_size:?}");

        let compiled = Self::transpile(program.as_ref(), is_debug, max_trace_size);

        Self { program, compiled, input: VecDeque::new() }
    }

    /// Transpile the program, saving the JIT function.
    #[tracing::instrument(name = "MinimalExecutor::transpile", level = "debug", skip(program))]
    fn transpile(program: &Program, is_debug: bool, max_trace_size: Option<u64>) -> JitFunction {
        let trace_buf_size = max_trace_size.unwrap_or(0);

        let mut backend = TranspilerBackend::new(
            program.instructions.len(),
            2_u64.pow(MAX_LOG_ADDR as u32) as usize,
            trace_buf_size,
            program.pc_start_abs,
            program.pc_base,
            8,
        )
        .expect("Failed to create transpiler backend");

        backend.register_ecall_handler(crate::minimal::ecall::sp1_ecall_handler);

        if is_debug {
            Self::transpile_instructions(DebugBackend::new(backend), program, trace_buf_size > 0)
        } else {
            Self::transpile_instructions(backend, program, trace_buf_size > 0)
        }
    }

    /// Create a new minimal executor with no tracing or debugging.
    #[must_use]
    pub fn simple(program: Arc<Program>) -> Self {
        Self::new(program, false, None)
    }

    /// Create a new minimal executor with tracing.
    ///
    /// # Arguments
    ///
    /// * `program` - The program to execute.
    /// * `max_trace_size` - The maximum trace size in terms of [`MemValue`]s. If not set, it will
    ///   be set to 2 gb worth of memory events.
    #[must_use]
    pub fn tracing(program: Arc<Program>, max_trace_size: u64) -> Self {
        Self::new(program, false, Some(max_trace_size))
    }

    /// Create a new minimal executor with debugging.
    #[must_use]
    pub fn debug(program: Arc<Program>) -> Self {
        Self::new(program, true, None)
    }

    /// Add input to the executor.
    pub fn with_input(&mut self, input: &[u8]) {
        self.input.push_back(input.to_vec());
    }

    /// Execute the program. Returning a trace chunk if the program has not completed.
    pub fn execute_chunk(&mut self) -> Option<TraceChunkRaw> {
        if !self.input.is_empty() {
            self.compiled.set_input_buffer(std::mem::take(&mut self.input));
        }

        // SAFETY: The backend is assumed to output valid JIT functions.
        unsafe { self.compiled.call() }
    }

    /// Get the registers of the JIT function.
    #[must_use]
    pub fn registers(&self) -> [u64; 32] {
        self.compiled.registers
    }

    /// Get the program counter of the JIT function.
    #[must_use]
    pub fn pc(&self) -> u64 {
        self.compiled.pc
    }

    /// Check if the program has halted.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.compiled.pc == HALT_PC
    }

    /// Get the current value at an address.
    #[must_use]
    pub fn get_memory_value(&self, addr: u64) -> MemValue {
        MemoryView::new(&self.compiled.memory).get(addr)
    }

    /// Get the program of the JIT function.
    #[must_use]
    pub fn program(&self) -> Arc<Program> {
        self.program.clone()
    }

    /// Get the current clock of the JIT function.
    ///
    /// This clock is incremented by 8 or 256 depending on the instruction.
    #[must_use]
    pub fn clk(&self) -> u64 {
        self.compiled.clk
    }

    /// Get the global clock of the JIT function.
    ///
    /// This clock is incremented by 1 per instruction.
    #[must_use]
    pub fn global_clk(&self) -> u64 {
        self.compiled.global_clk
    }

    /// Get the exit code of the JIT function.
    #[must_use]
    pub fn exit_code(&self) -> u32 {
        self.compiled.exit_code
    }

    /// Get the public values stream of the JIT function.
    #[must_use]
    pub fn public_values_stream(&self) -> &Vec<u8> {
        &self.compiled.public_values_stream
    }

    /// Consume self, and return the public values stream.
    #[must_use]
    pub fn into_public_values_stream(self) -> Vec<u8> {
        self.compiled.public_values_stream
    }

    /// Get the hints of the JIT function.
    #[must_use]
    pub fn hints(&self) -> &[(u64, Vec<u8>)] {
        &self.compiled.hints
    }

    /// Get the lengths of all the hints.
    #[must_use]
    pub fn hint_lens(&self) -> Vec<usize> {
        self.compiled.hints.iter().map(|(_, hint)| hint.len()).collect()
    }

    /// Get a view of the current memory of the JIT function.
    #[must_use]
    pub fn memory(&self) -> MemoryView<'_> {
        MemoryView::new(&self.compiled.memory)
    }

    /// Get an unsafe memory view of the JIT function.
    ///
    /// This allows reading without lifetime and mutability constraints.
    #[must_use]
    #[allow(clippy::cast_ptr_alignment)]
    pub fn unsafe_memory(&self) -> UnsafeMemory {
        let view = self.memory();
        let entry_ptr = view.memory.as_ptr() as *mut MemValue;
        UnsafeMemory { ptr: NonNull::new(entry_ptr).unwrap() }
    }

    /// Reset the JIT function, to start from the beginning of the program.
    pub fn reset(&mut self) {
        self.compiled.reset();

        let _ = std::mem::take(&mut self.input);
    }

    fn transpile_instructions<B: RiscvTranspiler>(
        mut backend: B,
        program: &Program,
        tracing: bool,
    ) -> JitFunction {
        for instruction in program.instructions.iter() {
            backend.start_instr();

            match instruction.opcode {
                Opcode::LB
                | Opcode::LH
                | Opcode::LW
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::LD
                | Opcode::LWU => {
                    Self::transpile_load_instruction(&mut backend, instruction, tracing);
                }
                Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => {
                    Self::transpile_store_instruction(&mut backend, instruction, tracing);
                }
                Opcode::BEQ
                | Opcode::BNE
                | Opcode::BLT
                | Opcode::BGE
                | Opcode::BLTU
                | Opcode::BGEU => {
                    Self::transpile_branch_instruction(&mut backend, instruction);
                }
                Opcode::JAL | Opcode::JALR => {
                    Self::transpile_jump_instruction(&mut backend, instruction);
                }
                Opcode::ADD
                | Opcode::ADDI
                | Opcode::SUB
                | Opcode::XOR
                | Opcode::OR
                | Opcode::AND
                | Opcode::SLL
                | Opcode::SRL
                | Opcode::SRA
                | Opcode::SLT
                | Opcode::SLTU
                | Opcode::MUL
                | Opcode::MULH
                | Opcode::MULHU
                | Opcode::MULHSU
                | Opcode::DIV
                | Opcode::DIVU
                | Opcode::REM
                | Opcode::REMU
                | Opcode::ADDW
                | Opcode::SUBW
                | Opcode::SLLW
                | Opcode::SRLW
                | Opcode::SRAW
                | Opcode::DIVUW
                | Opcode::DIVW
                | Opcode::MULW
                | Opcode::REMUW
                | Opcode::REMW
                    if instruction.is_alu_instruction() =>
                {
                    Self::transpile_alu_instruction(&mut backend, instruction);
                }
                Opcode::AUIPC => {
                    let (rd, imm) = instruction.u_type();
                    backend.auipc(rd.into(), imm);
                }
                Opcode::LUI => {
                    let (rd, imm) = instruction.u_type();
                    backend.lui(rd.into(), imm);
                }
                Opcode::ECALL => {
                    backend.ecall();
                }
                Opcode::EBREAK | Opcode::UNIMP => {
                    backend.unimp();
                }
                _ => panic!("Invalid instruction: {:?}", instruction.opcode),
            }

            backend.end_instr();
        }

        let mut finalized = backend.finalize().expect("Failed to finalize function");
        finalized.with_initial_memory_image(program.memory_image.clone());

        finalized
    }

    fn transpile_load_instruction<B: RiscvTranspiler>(
        backend: &mut B,
        instruction: &Instruction,
        tracing: bool,
    ) {
        let (rd, rs1, imm) = instruction.i_type();

        // For each load, we want to trace the value at the address as well as the previous clock
        // at that address.
        if tracing {
            backend.trace_mem_value(rs1.into(), imm);
        }

        match instruction.opcode {
            Opcode::LB => backend.lb(rd.into(), rs1.into(), imm),
            Opcode::LH => backend.lh(rd.into(), rs1.into(), imm),
            Opcode::LW => backend.lw(rd.into(), rs1.into(), imm),
            Opcode::LBU => backend.lbu(rd.into(), rs1.into(), imm),
            Opcode::LHU => backend.lhu(rd.into(), rs1.into(), imm),
            Opcode::LD => backend.ld(rd.into(), rs1.into(), imm),
            Opcode::LWU => backend.lwu(rd.into(), rs1.into(), imm),
            _ => unreachable!("Invalid load opcode: {:?}", instruction.opcode),
        }
    }

    fn transpile_store_instruction<B: RiscvTranspiler>(
        backend: &mut B,
        instruction: &Instruction,
        tracing: bool,
    ) {
        let (rs1, rs2, imm) = instruction.s_type();

        // For stores, its the same logic as a load, we want the last known clk and value at the
        // address.
        if tracing {
            backend.trace_mem_value(rs2.into(), imm);
        }

        // Note: We switch around rs1 and rs2 operaneds to align with the executor.
        match instruction.opcode {
            Opcode::SB => backend.sb(rs2.into(), rs1.into(), imm),
            Opcode::SH => backend.sh(rs2.into(), rs1.into(), imm),
            Opcode::SW => backend.sw(rs2.into(), rs1.into(), imm),
            Opcode::SD => backend.sd(rs2.into(), rs1.into(), imm),
            _ => unreachable!("Invalid store opcode: {:?}", instruction.opcode),
        }
    }

    fn transpile_branch_instruction<B: RiscvTranspiler>(
        backend: &mut B,
        instruction: &Instruction,
    ) {
        let (rs1, rs2, imm) = instruction.b_type();
        match instruction.opcode {
            Opcode::BEQ => backend.beq(rs1.into(), rs2.into(), imm),
            Opcode::BNE => backend.bne(rs1.into(), rs2.into(), imm),
            Opcode::BLT => backend.blt(rs1.into(), rs2.into(), imm),
            Opcode::BGE => backend.bge(rs1.into(), rs2.into(), imm),
            Opcode::BLTU => backend.bltu(rs1.into(), rs2.into(), imm),
            Opcode::BGEU => backend.bgeu(rs1.into(), rs2.into(), imm),
            _ => unreachable!("Invalid branch opcode: {:?}", instruction.opcode),
        }
    }

    fn transpile_jump_instruction<B: RiscvTranspiler>(backend: &mut B, instruction: &Instruction) {
        match instruction.opcode {
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                backend.jal(rd.into(), imm);
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();

                backend.jalr(rd.into(), rs1.into(), imm);
            }
            _ => unreachable!("Invalid jump opcode: {:?}", instruction.opcode),
        }
    }

    fn transpile_alu_instruction<B: RiscvTranspiler>(backend: &mut B, instruction: &Instruction) {
        let (rd, b, c): (RiscRegister, RiscOperand, RiscOperand) = if !instruction.imm_c {
            let (rd, rs1, rs2) = instruction.r_type();

            (rd.into(), rs1.into(), rs2.into())
        } else if !instruction.imm_b && instruction.imm_c {
            let (rd, rs1, imm) = instruction.i_type();

            (rd.into(), rs1.into(), imm.into())
        } else {
            debug_assert!(instruction.imm_b && instruction.imm_c);
            let (rd, b, c) =
                (Register::from_u8(instruction.op_a), instruction.op_b, instruction.op_c);

            (rd.into(), b.into(), c.into())
        };

        match instruction.opcode {
            Opcode::ADD | Opcode::ADDI => backend.add(rd, b, c),
            Opcode::SUB => backend.sub(rd, b, c),
            Opcode::XOR => backend.xor(rd, b, c),
            Opcode::OR => backend.or(rd, b, c),
            Opcode::AND => backend.and(rd, b, c),
            Opcode::SLL => backend.sll(rd, b, c),
            Opcode::SRL => backend.srl(rd, b, c),
            Opcode::SRA => backend.sra(rd, b, c),
            Opcode::SLT => backend.slt(rd, b, c),
            Opcode::SLTU => backend.sltu(rd, b, c),
            Opcode::MUL => backend.mul(rd, b, c),
            Opcode::MULH => backend.mulh(rd, b, c),
            Opcode::MULHU => backend.mulhu(rd, b, c),
            Opcode::MULHSU => backend.mulhsu(rd, b, c),
            Opcode::DIV => backend.div(rd, b, c),
            Opcode::DIVU => backend.divu(rd, b, c),
            Opcode::REM => backend.rem(rd, b, c),
            Opcode::REMU => backend.remu(rd, b, c),
            Opcode::ADDW => backend.addw(rd, b, c),
            Opcode::SUBW => backend.subw(rd, b, c),
            Opcode::SLLW => backend.sllw(rd, b, c),
            Opcode::SRLW => backend.srlw(rd, b, c),
            Opcode::SRAW => backend.sraw(rd, b, c),
            Opcode::MULW => backend.mulw(rd, b, c),
            Opcode::DIVUW => backend.divuw(rd, b, c),
            Opcode::DIVW => backend.divw(rd, b, c),
            Opcode::REMUW => backend.remuw(rd, b, c),
            Opcode::REMW => backend.remw(rd, b, c),
            _ => unreachable!("Invalid ALU opcode: {:?}", instruction.opcode),
        }
    }
}

impl debug::DebugState for MinimalExecutor {
    fn current_state(&self) -> debug::State {
        let registers = self.registers();
        debug::State { pc: self.pc(), clk: self.clk(), global_clk: self.global_clk(), registers }
    }

    fn new_debug_receiver(&mut self) -> Option<mpsc::Receiver<Option<debug::State>>> {
        self.compiled
            .debug_sender
            .is_none()
            .then(|| {
                let (tx, rx) = mpsc::sync_channel(0);
                self.compiled.debug_sender = Some(tx);
                Some(rx)
            })
            .flatten()
    }
}

/// An unsafe memory view
///
/// This allows reading without lifetime and mutability constraints.
pub struct UnsafeMemory {
    ptr: NonNull<MemValue>,
}

unsafe impl Send for UnsafeMemory {}
unsafe impl Sync for UnsafeMemory {}

impl UnsafeMemory {
    /// Get a value from the memory.
    ///
    /// # Safety
    /// As the function strictly breaks the lifetime rules, it is unsafe and should only be used
    /// under strict guarantees that the memory is not being dropped or the same address being
    /// accessed is being modified.
    #[must_use]
    pub unsafe fn get(&self, addr: u64) -> MemValue {
        let word_address = addr / 8;
        let entry_ptr = self.ptr.as_ptr();
        std::ptr::read(entry_ptr.add(word_address as usize))
    }
}
