#![allow(clippy::items_after_statements)]
#![allow(unknown_lints)]
#![allow(clippy::manual_checked_ops)]

use sp1_jit::{
    debug::{self, DebugState},
    MemValue, RiscRegister, SyscallContext, TraceChunkHeader, TraceChunkRaw,
};

use std::{
    collections::VecDeque,
    io,
    ptr::NonNull,
    sync::{mpsc, Arc},
};

#[cfg(feature = "profiling")]
use hashbrown::HashMap;

use crate::{
    minimal::ecall::ecall_handler, Instruction, Opcode, Program, Register, SyscallCode,
    CLK_INC as CLK_INC_32, HALT_PC, PC_INC as PC_INC_32,
};

mod cow;
use cow::MaybeCowMemory;
mod trace;
use trace::TraceChunkBuffer;

const CLK_INC: u64 = CLK_INC_32 as u64;
const PC_INC: u64 = PC_INC_32 as u64;

/// A minimal trace executor.
pub struct MinimalExecutor {
    program: Arc<Program>,
    input: VecDeque<Vec<u8>>,
    registers: [u64; 32],
    memory: Box<MaybeCowMemory<MemValue>>,
    traces: Option<TraceChunkBuffer>,
    pc: u64,
    clk: u64,
    global_clk: u64,
    exit_code: u32,
    max_trace_size: Option<u64>,
    public_values_stream: Vec<u8>,
    hints: Vec<(u64, Vec<u8>)>,
    maybe_unconstrained: Option<UnconstrainedCtx>,
    debug_sender: Option<mpsc::SyncSender<Option<debug::State>>>,
    #[cfg(feature = "profiling")]
    profiler: Option<(crate::profiler::Profiler, std::io::BufWriter<std::fs::File>)>,
    /// Cycle tracker start times and depths, keyed by label name.
    #[cfg(feature = "profiling")]
    cycle_tracker_starts: HashMap<String, (u64, u32)>,
    /// Accumulated cycle counts for report variants, keyed by label name.
    #[cfg(feature = "profiling")]
    cycle_tracker_totals: HashMap<String, u64>,
    /// Invocation counts for report variants, keyed by label name.
    #[cfg(feature = "profiling")]
    invocation_tracker: HashMap<String, u64>,
}

#[derive(Debug)]
struct UnconstrainedCtx {
    pub registers: [u64; 32],
    pub pc: u64,
    pub clk: u64,
}

// Note: Most syscalls are inaccessible in unconstrained mode,
// so we dont need to explicitly check for unconstrained
// mode here.
impl SyscallContext for MinimalExecutor {
    fn rr(&self, reg: RiscRegister) -> u64 {
        self.registers[reg as usize]
    }

    fn mr(&mut self, addr: u64) -> u64 {
        let mem_value = self.memory.entry(addr).or_default();
        if self.traces.is_some() {
            unsafe {
                self.traces.as_mut().unwrap_unchecked().extend(&[*mem_value]);
            }

            mem_value.clk = self.clk;
        }
        mem_value.value
    }

    fn mw(&mut self, addr: u64, val: u64) {
        let mem_value = self.memory.entry(addr).or_default();
        if self.traces.is_some() {
            unsafe {
                self.traces.as_mut().unwrap_unchecked().extend(&[*mem_value]);
            }
        }

        mem_value.clk = self.clk;
        mem_value.value = val;

        if self.traces.is_some() {
            unsafe {
                self.traces.as_mut().unwrap_unchecked().extend(&[*mem_value]);
            }
        }
    }

    fn mr_slice(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64> {
        let len = len as u64;
        for i in 0..len {
            let mem_value = self.memory.entry(addr + i * 8).or_default();
            if self.traces.is_some() {
                unsafe {
                    self.traces.as_mut().unwrap_unchecked().extend(&[*mem_value]);
                }
                mem_value.clk = self.clk;
            }
        }

        (addr..addr + len * 8).step_by(8).map(|addr| unsafe {
            // SAFETY: We just inserted the entry if it didn't exist, so we know it exists
            &self.memory.get(addr).unwrap_unchecked().value
        })
    }

    fn mr_slice_unsafe(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64> {
        let len = len as u64;
        for i in 0..len {
            let mem_value = self.memory.entry(addr + i * 8).or_default();
            if self.traces.is_some() {
                unsafe {
                    self.traces.as_mut().unwrap_unchecked().extend(&[*mem_value]);
                }
            }
        }

        (addr..addr + len * 8).step_by(8).map(|addr| unsafe {
            // SAFETY: We just inserted the entry if it didn't exist, so we know it exists
            &self.memory.get(addr).unwrap_unchecked().value
        })
    }

    fn mr_slice_no_trace(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64> {
        let len = len as u64;

        (addr..addr + len * 8).step_by(8).map(|addr| self.memory.get(addr).map_or(&0, |v| &v.value))
    }

    fn mw_slice(&mut self, addr: u64, vals: &[u64]) {
        for (i, val) in vals.iter().enumerate() {
            self.mw(addr + 8 * i as u64, *val);
        }
    }

    fn input_buffer(&mut self) -> &mut VecDeque<Vec<u8>> {
        &mut self.input
    }

    fn public_values_stream(&mut self) -> &mut Vec<u8> {
        &mut self.public_values_stream
    }

    fn enter_unconstrained(&mut self) -> io::Result<()> {
        assert!(
            self.maybe_unconstrained.is_none(),
            "Enter unconstrained called but context is already present, this is a bug."
        );
        self.maybe_unconstrained =
            Some(UnconstrainedCtx { registers: self.registers, pc: self.pc, clk: self.clk });
        self.memory.copy_on_write();

        Ok(())
    }

    fn exit_unconstrained(&mut self) {
        let unconstrained = self
            .maybe_unconstrained
            .take()
            .expect("Exit unconstrained called but not context is present, this is a bug.");
        self.registers = unconstrained.registers;
        self.pc = unconstrained.pc;
        self.clk = unconstrained.clk;
        self.memory.owned();
    }

    fn trace_hint(&mut self, addr: u64, value: Vec<u8>) {
        if self.traces.is_some() {
            self.hints.push((addr, value));
        }
    }

    fn mw_hint(&mut self, addr: u64, val: u64) {
        self.memory.insert(addr, MemValue { clk: 0, value: val });
    }

    fn bump_memory_clk(&mut self) {
        self.clk = self.clk.wrapping_add(1);
    }

    fn set_exit_code(&mut self, exit_code: u32) {
        self.exit_code = exit_code;
    }

    fn is_unconstrained(&self) -> bool {
        self.maybe_unconstrained.is_some()
    }

    fn global_clk(&self) -> u64 {
        self.global_clk
    }

    #[cfg(feature = "profiling")]
    fn cycle_tracker_start(&mut self, name: &str) -> u32 {
        let depth = self.cycle_tracker_starts.len() as u32;
        self.cycle_tracker_starts.insert(name.to_string(), (self.global_clk, depth));
        depth
    }

    #[cfg(feature = "profiling")]
    fn cycle_tracker_end(&mut self, name: &str) -> Option<(u64, u32)> {
        self.cycle_tracker_starts
            .remove(name)
            .map(|(start, depth)| (self.global_clk.saturating_sub(start), depth))
    }

    #[cfg(feature = "profiling")]
    fn cycle_tracker_report_end(&mut self, name: &str) -> Option<(u64, u32)> {
        self.cycle_tracker_starts.remove(name).map(|(start, depth)| {
            let cycles = self.global_clk.saturating_sub(start);
            // Accumulate to totals for ExecutionReport
            *self.cycle_tracker_totals.entry(name.to_string()).or_insert(0) += cycles;
            *self.invocation_tracker.entry(name.to_string()).or_insert(0) += 1;
            (cycles, depth)
        })
    }
}

impl MinimalExecutor {
    /// Create a new minimal executor and transpiles the program.
    #[must_use]
    pub fn new(program: Arc<Program>, _debug: bool, max_trace_size: Option<u64>) -> Self {
        // Insert the memory image.
        let mut memory = MaybeCowMemory::new_owned();
        let pc = program.pc_start_abs;
        for (addr, value) in program.memory_image.iter() {
            memory.insert(*addr, MemValue { clk: 0, value: *value });
        }

        let mut result = Self {
            program,
            input: VecDeque::new(),
            registers: [0; 32],
            global_clk: 0,
            clk: 1,
            pc,
            memory: Box::new(memory),
            traces: None,
            max_trace_size,
            public_values_stream: Vec::new(),
            hints: Vec::new(),
            maybe_unconstrained: None,
            debug_sender: None,
            exit_code: 0,
            #[cfg(feature = "profiling")]
            profiler: None,
            #[cfg(feature = "profiling")]
            cycle_tracker_starts: HashMap::new(),
            #[cfg(feature = "profiling")]
            cycle_tracker_totals: HashMap::new(),
            #[cfg(feature = "profiling")]
            invocation_tracker: HashMap::new(),
        };
        result.maybe_setup_profiler();
        result
    }

    /// WARNING: This function's API is subject to change without a major version bump.
    ///
    /// If the feature `"profiling"` is enabled, this sets up the profiler. Otherwise, it does
    /// nothing.
    ///
    /// The profiler is configured by the following environment variables:
    ///
    /// - `TRACE_FILE`: writes Gecko traces to this path. If unspecified, the profiler is disabled.
    /// - `TRACE_SAMPLE_RATE`: The period between clock cycles where samples are taken. Defaults to
    ///   1.
    #[inline]
    #[allow(unused_variables)]
    fn maybe_setup_profiler(&mut self) {
        #[cfg(feature = "profiling")]
        {
            use crate::profiler::Profiler;
            use std::{fs::File, io::BufWriter};

            let trace_buf = std::env::var("TRACE_FILE").ok().map(|file| {
                let file = File::create(file).unwrap();
                BufWriter::new(file)
            });

            if let Some(trace_buf) = trace_buf {
                eprintln!("Profiling enabled");

                let sample_rate = std::env::var("TRACE_SAMPLE_RATE")
                    .ok()
                    .and_then(|rate| {
                        eprintln!("Profiling sample rate: {rate}");
                        rate.parse::<u32>().ok()
                    })
                    .unwrap_or(1);

                self.profiler =
                    Some((Profiler::from_program(&self.program, sample_rate as u64), trace_buf));
            }
        }
    }

    /// Create a new minimal executor with no tracing or debugging.
    #[must_use]
    pub fn simple(program: Arc<Program>) -> Self {
        Self::new(program, false, None)
    }

    /// Create a new minimal executor with tracing.
    #[must_use]
    pub fn tracing(program: Arc<Program>, max_trace_size: u64) -> Self {
        Self::new(program, true, Some(max_trace_size))
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
    #[allow(clippy::redundant_closure_for_method_calls)]
    pub fn execute_chunk(&mut self) -> Option<TraceChunkRaw> {
        if self.is_done() {
            return None;
        }

        if let Some(max_trace_size) = self.max_trace_size {
            let capacity = trace_capacity(max_trace_size);

            self.traces = Some(TraceChunkBuffer::new(capacity));
        }

        if self.traces.is_some() {
            unsafe {
                let traces = self.traces.as_mut().unwrap_unchecked();
                traces.write_start_registers(&self.registers);
                traces.write_pc_start(self.pc);
                traces.write_clk_start(self.clk);
            }
        }

        // Keep track of the start hint index for this chunk,
        // we dont want to give any subsequent chunks that were already given to the previous
        // chunks.
        let start_hint_idx = self.hints.len();

        while !self.execute_instruction() {}

        #[cfg(feature = "profiling")]
        if self.is_done() {
            if let Some((profiler, writer)) = self.profiler.take() {
                profiler.write(writer).expect("Failed to write profile to output file");
            }
        }

        if self.traces.is_some() {
            unsafe {
                let traces = self.traces.as_mut().unwrap_unchecked();
                traces.write_clk_end(self.clk);
            }
        }

        // Incase the chunk ends before we actually call `syscall_hint_read`, we will give the
        // chunk the remaining hints and input.
        let traces = std::mem::take(&mut self.traces);

        traces.map(|trace| unsafe {
            TraceChunkRaw::new(
                trace.into(),
                self.hints
                    .iter()
                    .skip(start_hint_idx)
                    .map(|(_, hint)| hint.len())
                    .chain(self.input.iter().map(|input| input.len()))
                    .collect(),
            )
        })
    }

    /// Check if the program has halted.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.pc == HALT_PC
    }

    /// Get the program counter of the executor
    #[must_use]
    pub fn pc(&self) -> u64 {
        self.pc
    }

    /// Get the current clock of the executor
    ///
    /// This clock is incremented by 8 or 256 depending on the instruction.
    #[must_use]
    pub fn clk(&self) -> u64 {
        self.clk
    }

    /// Get the global clock of the executor
    ///
    /// This clock is incremented by 1 per instruction.
    #[must_use]
    pub fn global_clk(&self) -> u64 {
        self.global_clk
    }

    /// Get the program of the executor
    #[must_use]
    pub fn program(&self) -> Arc<Program> {
        self.program.clone()
    }

    /// Get the registers of the executor
    #[must_use]
    pub fn registers(&self) -> [u64; 32] {
        self.registers
    }

    /// Get the exit code of the executor
    #[must_use]
    pub fn exit_code(&self) -> u32 {
        self.exit_code
    }

    /// Get the public values stream of the executor
    #[must_use]
    pub fn public_values_stream(&self) -> &Vec<u8> {
        &self.public_values_stream
    }

    /// Consume self, and return the public values stream.
    #[must_use]
    pub fn into_public_values_stream(self) -> Vec<u8> {
        self.public_values_stream
    }

    /// Get the hints of the executor
    #[must_use]
    pub fn hints(&self) -> &Vec<(u64, Vec<u8>)> {
        &self.hints
    }

    /// Get the lengths of all the hints.
    #[must_use]
    pub fn hint_lens(&self) -> Vec<usize> {
        self.hints.iter().map(|(_, hint)| hint.len()).collect()
    }

    /// Get the accumulated cycle tracker totals (for report variants).
    #[cfg(feature = "profiling")]
    #[must_use]
    pub fn cycle_tracker_totals(&self) -> &HashMap<String, u64> {
        &self.cycle_tracker_totals
    }

    /// Get the invocation tracker (counts for report variants).
    #[cfg(feature = "profiling")]
    #[must_use]
    pub fn invocation_tracker(&self) -> &HashMap<String, u64> {
        &self.invocation_tracker
    }

    /// Take the cycle tracker totals, consuming them.
    #[cfg(feature = "profiling")]
    #[must_use]
    pub fn take_cycle_tracker_totals(&mut self) -> HashMap<String, u64> {
        std::mem::take(&mut self.cycle_tracker_totals)
    }

    /// Take the invocation tracker, consuming it.
    #[cfg(feature = "profiling")]
    #[must_use]
    pub fn take_invocation_tracker(&mut self) -> HashMap<String, u64> {
        std::mem::take(&mut self.invocation_tracker)
    }

    /// Get a view of the current memory of the executor
    #[must_use]
    pub fn get_memory_value(&self, addr: u64) -> MemValue {
        self.memory.get(addr).copied().unwrap_or_default()
    }

    /// Get an unsafe memory view of the executor.
    #[must_use]
    pub fn unsafe_memory(&self) -> UnsafeMemory {
        let ptr = (&raw const *self.memory).cast::<MaybeCowMemory<MemValue>>().cast_mut();
        UnsafeMemory { memory: NonNull::new(ptr).unwrap() }
    }

    /// Reset the executor, to start from the beginning of the program.
    pub fn reset(&mut self) {
        let _ = std::mem::take(&mut self.input);
        todo!()
    }

    fn execute_instruction(&mut self) -> bool {
        let program = self.program.clone();
        let instruction = program.fetch(self.pc).unwrap();
        if let Some(sender) = &self.debug_sender {
            sender.send(Some(self.current_state())).expect("Failed to send debug state");
        }
        #[cfg(feature = "profiling")]
        if let Some((ref mut profiler, _)) = self.profiler {
            if self.maybe_unconstrained.is_none() {
                profiler.record(self.global_clk, self.pc);
            }
        }

        let mut next_pc = self.pc.wrapping_add(PC_INC);
        let mut next_clk = self.clk.wrapping_add(CLK_INC);
        if instruction.is_alu_instruction() {
            self.execute_alu(instruction);
        } else if instruction.is_memory_load_instruction() {
            self.execute_load(instruction);
        } else if instruction.is_memory_store_instruction() {
            self.execute_store(instruction);
        } else if instruction.is_branch_instruction() {
            self.execute_branch(instruction, &mut next_pc);
        } else if instruction.is_jump_instruction() {
            self.execute_jump(instruction, &mut next_pc);
        } else if instruction.is_utype_instruction() {
            self.execute_utype(instruction);
        } else if instruction.is_ecall_instruction() {
            self.execute_ecall(instruction, &mut next_pc, &mut next_clk);
        } else {
            unreachable!("Invalid opcode for `execute_instruction`: {:?}", instruction.opcode)
        }

        self.registers[0] = 0;
        self.pc = next_pc;
        self.clk = next_clk;
        if self.maybe_unconstrained.is_none() {
            self.global_clk = self.global_clk.wrapping_add(1);
        }

        let trace_buf_size_exceeded = self.traces.as_ref().is_some_and(|trace| {
            trace.num_mem_reads()
                >= self.max_trace_size.expect("If traces is some, max_trace_size must be some")
        });

        self.is_done() || trace_buf_size_exceeded
    }

    /// Execute a load instruction.
    #[inline]
    fn execute_load(&mut self, instruction: &Instruction) {
        let (rd, rs1, imm_offset) = instruction.i_type();
        let base = self.registers[rs1 as usize];
        let addr = base.wrapping_add(imm_offset);
        let aligned_addr = addr & !0b111;

        let mem_value = self.memory.entry(aligned_addr).or_default();
        if self.traces.is_some() && self.maybe_unconstrained.is_none() {
            unsafe {
                self.traces.as_mut().unwrap_unchecked().extend(&[*mem_value]);
            }
        }

        mem_value.clk = self.clk + 1;
        let value = mem_value.value;

        self.registers[rd as usize] = match instruction.opcode {
            Opcode::LB => ((value >> ((addr % 8) * 8)) & 0xFF) as i8 as i64 as u64,
            Opcode::LH => {
                assert!(
                    addr.is_multiple_of(2),
                    "LH must be aligned to 2 bytes (base=0x{base:x}, offset=0x{imm_offset:x})"
                );
                ((value >> (((addr / 2) % 4) * 16)) & 0xFFFF) as i16 as i64 as u64
            }
            Opcode::LW => {
                assert!(
                    addr.is_multiple_of(4),
                    "LW must be aligned to 4 bytes (base=0x{base:x}, offset=0x{imm_offset:x})"
                );
                ((value >> (((addr / 4) % 2) * 32)) & 0xFFFFFFFF) as i32 as u64
            }
            Opcode::LBU => ((value >> ((addr % 8) * 8)) & 0xFF) as u8 as u64,
            Opcode::LHU => {
                assert!(
                    addr.is_multiple_of(2),
                    "LHU must be aligned to 2 bytes (base=0x{base:x}, offset=0x{imm_offset:x})"
                );
                ((value >> (((addr / 2) % 4) * 16)) & 0xFFFF) as u16 as u64
            }
            // RISCV-64
            Opcode::LWU => {
                assert!(
                    addr.is_multiple_of(4),
                    "LWU must be aligned to 4 bytes (base=0x{base:x}, offset=0x{imm_offset:x})"
                );
                (value >> (((addr / 4) % 2) * 32)) & 0xFFFFFFFF
            }
            Opcode::LD => {
                assert!(
                    addr.is_multiple_of(8),
                    "LD must be aligned to 8 bytes (base=0x{base:x}, offset=0x{imm_offset:x})"
                );
                value
            }
            _ => unreachable!("Invalid opcode for `execute_load`: {:?}", instruction.opcode),
        };
    }

    /// When we store, we need to track the previous value at the address
    #[inline]
    fn execute_store(&mut self, instruction: &Instruction) {
        let (rs1, rs2, imm_offset) = instruction.s_type();
        let src = self.registers[rs1 as usize];
        let base = self.registers[rs2 as usize];
        let addr = base.wrapping_add(imm_offset);
        let aligned_addr = addr & !0b111;

        // Align the address to the lower word
        let last_value = self.mem_read_untracked(aligned_addr);
        let value = match instruction.opcode {
            Opcode::SB => {
                let shift = (addr % 8) * 8;
                ((src & 0xFF) << shift) | (last_value & !(0xFF << shift))
            }
            Opcode::SH => {
                assert!(addr.is_multiple_of(2), "SH must be aligned to 2 bytes");
                let shift = ((addr / 2) % 4) * 16;
                ((src & 0xFFFF) << shift) | (last_value & !(0xFFFF << shift))
            }
            Opcode::SW => {
                assert!(addr.is_multiple_of(4), "SW must be aligned to 4 bytes");
                let shift = ((addr / 4) % 2) * 32;
                ((src & 0xFFFFFFFF) << shift) | (last_value & !(0xFFFFFFFF << shift))
            }
            // RISCV-64
            Opcode::SD => {
                assert!(addr.is_multiple_of(8), "SD must be aligned to 8 bytes");
                src
            }
            _ => unreachable!(),
        };
        let mem_value = self.memory.entry(aligned_addr).or_default();
        if self.traces.is_some() && self.maybe_unconstrained.is_none() {
            unsafe {
                self.traces.as_mut().unwrap_unchecked().extend(&[*mem_value]);
            }
        }
        mem_value.clk = self.clk + 1;
        mem_value.value = value;
    }

    /// Execute an ALU instruction.
    #[inline]
    fn execute_alu(&mut self, instruction: &Instruction) {
        let rd = instruction.op_a as usize;
        let b = if instruction.imm_b {
            instruction.op_b
        } else {
            self.registers[instruction.op_b as usize]
        };
        let c = if instruction.imm_c {
            instruction.op_c
        } else {
            self.registers[instruction.op_c as usize]
        };
        let a = match instruction.opcode {
            Opcode::ADD | Opcode::ADDI => b.wrapping_add(c),
            Opcode::SUB => b.wrapping_sub(c),
            Opcode::XOR => b ^ c,
            Opcode::OR => b | c,
            Opcode::AND => b & c,
            Opcode::SLL => b << (c & 0x3f),
            Opcode::SRL => b >> (c & 0x3f),
            Opcode::SRA => ((b as i64) >> (c & 0x3f)) as u64,
            Opcode::SLT => {
                if (b as i64) < (c as i64) {
                    1
                } else {
                    0
                }
            }
            Opcode::SLTU => {
                if b < c {
                    1
                } else {
                    0
                }
            }
            Opcode::MUL => (b as i64).wrapping_mul(c as i64) as u64,
            Opcode::MULH => (((b as i64) as i128).wrapping_mul((c as i64) as i128) >> 64) as u64,
            Opcode::MULHU => ((b as u128 * c as u128) >> 64) as u64,
            Opcode::MULHSU => ((((b as i64) as i128) * (c as i128)) >> 64) as u64,
            Opcode::DIV => {
                if c == 0 {
                    u64::MAX
                } else {
                    (b as i64).wrapping_div(c as i64) as u64
                }
            }
            Opcode::DIVU => {
                if c == 0 {
                    u64::MAX
                } else {
                    b / c
                }
            }
            Opcode::REM => {
                if c == 0 {
                    b
                } else {
                    (b as i64).wrapping_rem(c as i64) as u64
                }
            }
            Opcode::REMU => {
                if c == 0 {
                    b
                } else {
                    b % c
                }
            }
            // RISCV-64 word operations
            Opcode::ADDW => (b as i32).wrapping_add(c as i32) as i64 as u64,
            Opcode::SUBW => (b as i32).wrapping_sub(c as i32) as i64 as u64,
            Opcode::MULW => (b as i32).wrapping_mul(c as i32) as i64 as u64,
            Opcode::DIVW => {
                if c as i32 == 0 {
                    u64::MAX
                } else {
                    (b as i32).wrapping_div(c as i32) as i64 as u64
                }
            }
            Opcode::DIVUW => {
                if c as i32 == 0 {
                    u64::MAX
                } else {
                    ((b as u32 / c as u32) as i32) as i64 as u64
                }
            }
            Opcode::REMW => {
                if c as i32 == 0 {
                    (b as i32) as u64
                } else {
                    (b as i32).wrapping_rem(c as i32) as i64 as u64
                }
            }
            Opcode::REMUW => {
                if c as u32 == 0 {
                    (b as i32) as u64
                } else {
                    (((b as u32) % (c as u32)) as i32) as i64 as u64
                }
            }
            // RISCV-64 bit operations
            Opcode::SLLW => (((b as i64) << (c & 0x1f)) as i32) as i64 as u64,
            Opcode::SRLW => (((b as u32) >> ((c & 0x1f) as u32)) as i32) as u64,
            Opcode::SRAW => {
                (b as i32).wrapping_shr(((c as i64 & 0x1f) as i32) as u32) as i64 as u64
            }
            _ => unreachable!(),
        };
        self.registers[rd] = a;
    }

    /// Execute a jump instruction.
    fn execute_jump(&mut self, instruction: &Instruction, next_pc: &mut u64) {
        match instruction.opcode {
            Opcode::JAL => {
                let (rd, imm_offset) = instruction.j_type();
                let imm_offset_se = sign_extend_imm(imm_offset, 21);
                let pc = self.pc;
                *next_pc = ((pc as i64).wrapping_add(imm_offset_se)) as u64;
                self.registers[rd as usize] = pc.wrapping_add(4);
            }
            Opcode::JALR => {
                let (rd, rs1, imm_offset) = instruction.i_type();
                let base = self.registers[rs1 as usize] as i64;

                let imm_offset_se = sign_extend_imm(imm_offset, 12);
                self.registers[rd as usize] = self.pc.wrapping_add(PC_INC);
                // Calculate next PC: (rs1 + imm) & ~1
                *next_pc = (base.wrapping_add(imm_offset_se) as u64) & !1_u64;
            }
            _ => unreachable!("Invalid opcode for `execute_jump`: {:?}", instruction.opcode),
        }
    }

    /// Execute a branch instruction.
    fn execute_branch(&mut self, instruction: &Instruction, next_pc: &mut u64) {
        let (rs1, rs2, imm_offset) = instruction.b_type();
        let a = self.registers[rs1 as usize];
        let b = self.registers[rs2 as usize];
        let branch = match instruction.opcode {
            Opcode::BEQ => a == b,
            Opcode::BNE => a != b,
            Opcode::BLT => (a as i64) < (b as i64),
            Opcode::BGE => (a as i64) >= (b as i64),
            Opcode::BLTU => a < b,
            Opcode::BGEU => a >= b,
            _ => {
                unreachable!()
            }
        };
        if branch {
            *next_pc = self.pc.wrapping_add(imm_offset);
        }
    }

    /// Execute a U-type instruction.
    #[inline]
    fn execute_utype(&mut self, instruction: &Instruction) {
        let (rd, imm) = instruction.u_type();
        self.registers[rd as usize] = match instruction.opcode {
            Opcode::AUIPC => self.pc.wrapping_add(imm),
            Opcode::LUI => imm,
            _ => unreachable!(),
        };
    }

    #[inline]
    /// Execute an ecall instruction.
    fn execute_ecall(&mut self, instruction: &Instruction, next_pc: &mut u64, next_clk: &mut u64) {
        let opcode = instruction.opcode;
        assert!(instruction.is_ecall_instruction(), "Invalid ecall opcode: {opcode:?}");

        let code = SyscallCode::from_u32(self.registers[Register::X5 as usize] as u32);

        self.registers[Register::X5 as usize] = ecall_handler(self, code);

        // Handle special cases for syscalls.
        match code {
            // The pc and clk should have been updated by the ecall handler.
            SyscallCode::EXIT_UNCONSTRAINED => {
                // The `exit_unconstrained` resets the pc and clk to the values they were at when
                // the unconstrained block was entered.
                *next_pc = self.pc.wrapping_add(PC_INC);
                *next_clk = self.clk.wrapping_add(CLK_INC + 256);
            }
            SyscallCode::HALT => {
                // Explicity set the PC to one, to indicate that the program has halted.
                *next_pc = HALT_PC;
                *next_clk = next_clk.wrapping_add(256);
            }
            _ => {
                // In the normal case, we just want to advance to the next instruction, which has
                // already been done by the ecall handler.
                *next_clk = next_clk.wrapping_add(256);
            }
        }
    }

    fn mem_read_untracked(&self, addr: u64) -> u64 {
        let mem_value = self.memory.get(addr).copied().unwrap_or_default();
        mem_value.value
    }
}

fn sign_extend_imm(value: u64, bits: u8) -> i64 {
    let shift = 64 - bits;
    ((value as i64) << shift) >> shift
}

/// Worst-case memory operations a single instruction (precompile ecall) can emit.
/// The chunk-stop check only runs between instructions, so a single precompile can
/// emit this many trace entries beyond `max_trace_size` before the check fires.
/// `sha256_extend` is the worst case at 288; we use 512 for safety margin.
const MAX_SINGLE_INSTRUCTION_MEM_OPS: usize = 512;

fn trace_capacity(size: u64) -> usize {
    let events_bytes = size as usize * std::mem::size_of::<MemValue>();
    // Scale by 10/9 for proportional leeway on large traces.
    let events_bytes = events_bytes * 10 / 9;
    // Add fixed headroom for worst-case single-instruction overflow.
    let worst_case_bytes = MAX_SINGLE_INSTRUCTION_MEM_OPS * std::mem::size_of::<MemValue>();
    let header_bytes = std::mem::size_of::<TraceChunkHeader>();
    events_bytes + worst_case_bytes + header_bytes
}

impl DebugState for MinimalExecutor {
    fn current_state(&self) -> debug::State {
        debug::State {
            pc: self.pc,
            clk: self.clk,
            global_clk: self.global_clk,
            registers: self.registers,
        }
    }

    fn new_debug_receiver(&mut self) -> Option<mpsc::Receiver<Option<debug::State>>> {
        self.debug_sender
            .is_none()
            .then(|| {
                let (tx, rx) = std::sync::mpsc::sync_channel(0);
                self.debug_sender = Some(tx);
                Some(rx)
            })
            .flatten()
    }
}

/// An unsafe memory view
///
/// This allows reading without lifetime and mutability constraints.
pub struct UnsafeMemory {
    memory: NonNull<MaybeCowMemory<MemValue>>,
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
        let memory = self.memory.as_ref();
        memory.get(addr).copied().unwrap_or_default()
    }
}
