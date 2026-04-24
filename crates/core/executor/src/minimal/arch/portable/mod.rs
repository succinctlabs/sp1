#![allow(clippy::items_after_statements)]
#![allow(unknown_lints)]
#![allow(clippy::manual_checked_ops)]

use sp1_jit::{
    debug::{self, DebugState},
    trace_capacity, Interrupt, MemValue, PageProtValue, RiscRegister, SyscallContext,
    TraceChunkRaw,
};
use sp1_primitives::consts::{
    LOG_PAGE_SIZE, PROT_EXEC, PROT_FAILURE_EXEC, PROT_FAILURE_READ, PROT_FAILURE_WRITE, PROT_READ,
    PROT_WRITE,
};

use std::{
    collections::VecDeque,
    io,
    ptr::NonNull,
    sync::{mpsc, Arc},
};

#[cfg(feature = "profiling")]
use hashbrown::HashMap;

use hashbrown::HashMap as HBHashMap;
use rrs_lib::process_instruction;

use crate::{
    disassembler::InstructionTranspiler, memory::MAX_LOG_ADDR, minimal::ecall::ecall_handler,
    ExecutionError, ExecutionMode, Instruction, Opcode, Program, Register, SyscallCode,
    CLK_INC as CLK_INC_32, HALT_PC, PC_INC as PC_INC_32,
};
use std::marker::PhantomData;

mod cow;
use cow::LimitedMemory;
pub use cow::MaybeCowPageProt;
mod trace;
use trace::TraceChunkBuffer;

const CLK_INC: u64 = CLK_INC_32 as u64;
const PC_INC: u64 = PC_INC_32 as u64;

/// A minimal trace executor.
///
/// This executor runs SP1 program in current process. It does not limit the
/// memory used by SP1 program. For a malicious program, it might consume a lot
/// of memory, triggering OOM errors on the machine running SP1 provers.
/// As a result, it is only suitable for known programs. Please refer to
/// `sp1_core_executor_runner::MinimalExecutorRunner` for running arbitrary SP1 programs.
pub struct MinimalExecutor<M: ExecutionMode> {
    program: Arc<Program>,
    input: VecDeque<Vec<u8>>,
    registers: [u64; 32],
    memory: Box<LimitedMemory<MemValue>>,
    page_prots: MaybeCowPageProt,
    traces: Option<TraceChunkBuffer>,
    pc: u64,
    clk: u64,
    global_clk: u64,
    next_pc: u64,
    next_clk: u64,
    exit_code: u32,
    max_trace_size: Option<u64>,
    public_values_stream: Vec<u8>,
    hints: Vec<(u64, Vec<u8>)>,
    maybe_unconstrained: Option<UnconstrainedCtx>,
    debug_sender: Option<mpsc::SyncSender<Option<debug::State>>>,
    /// Transpiler for decoding untrusted instructions at runtime.
    transpiler: InstructionTranspiler,
    /// Cache of decoded instructions (keyed by raw instruction u32).
    decoded_instruction_cache: HBHashMap<u32, Instruction>,
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
    _mode: PhantomData<M>,
}

#[derive(Debug)]
struct UnconstrainedCtx {
    pub registers: [u64; 32],
    pub pc: u64,
    pub clk: u64,
}

// Note: Most syscalls are inaccessible in unconstrained mode,
// so we don't need to explicitly check for unconstrained
// mode here.
impl<M: ExecutionMode> SyscallContext for MinimalExecutor<M> {
    fn rr(&self, reg: RiscRegister) -> u64 {
        self.registers[reg as usize]
    }

    fn rw(&mut self, reg: RiscRegister, value: u64) {
        self.registers[reg as usize] = value;
    }

    fn set_next_pc(&mut self, pc: u64) {
        self.next_pc = pc;
    }

    fn mr_without_prot(&mut self, addr: u64) -> u64 {
        let mem_value = self.memory.get_mut(addr);
        if self.traces.is_some() {
            unsafe {
                self.traces.as_mut().unwrap_unchecked().extend(&[*mem_value]);
            }

            mem_value.clk = self.clk;
        }
        mem_value.value
    }

    fn mw_without_prot(&mut self, addr: u64, val: u64) {
        let mem_value = self.memory.get_mut(addr);
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

    fn mr_slice_without_prot(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64> {
        let len = len as u64;
        for i in 0..len {
            let mem_value = self.memory.get_mut(addr + i * 8);
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
            let mem_value = self.memory.get_mut(addr + i * 8);
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

    fn mw_slice_without_prot(&mut self, addr: u64, vals: &[u64]) {
        for (i, val) in vals.iter().enumerate() {
            self.mw_without_prot(addr + 8 * i as u64, *val);
        }
    }

    fn prot_slice_check(
        &mut self,
        addr: u64,
        len: usize,
        prot_bitmap: u8,
    ) -> Result<(), Interrupt> {
        if !M::PAGE_PROTECTION_ENABLED {
            return Ok(());
        }

        let first_page_idx = addr >> LOG_PAGE_SIZE;
        let last_page_idx = (addr + (len - 1) as u64 * 8) >> LOG_PAGE_SIZE;

        for page_idx in first_page_idx..=last_page_idx {
            let page_prot_value = self.page_prots.get(page_idx).copied().unwrap_or_default();

            // Trace the permission check.
            if self.traces.is_some() && self.maybe_unconstrained.is_none() {
                unsafe {
                    self.traces.as_mut().unwrap_unchecked().extend(&[page_prot_value.into()]);
                }
            }

            // Bump the timestamp on the permission entry.
            self.page_prots
                .insert(page_idx, PageProtValue { timestamp: self.clk, ..page_prot_value });

            // Check each permission bit.
            if (prot_bitmap & PROT_EXEC) != 0 && (page_prot_value.value & PROT_EXEC) == 0 {
                return Err(Interrupt { code: PROT_FAILURE_EXEC });
            }
            if (prot_bitmap & PROT_READ) != 0 && (page_prot_value.value & PROT_READ) == 0 {
                return Err(Interrupt { code: PROT_FAILURE_READ });
            }
            if (prot_bitmap & PROT_WRITE) != 0 && (page_prot_value.value & PROT_WRITE) == 0 {
                return Err(Interrupt { code: PROT_FAILURE_WRITE });
            }
        }
        Ok(())
    }

    fn page_prot_write(&mut self, addr: u64, val: u8) {
        assert!(addr.is_multiple_of(1 << LOG_PAGE_SIZE as u64), "addr must be page aligned");
        assert!(addr < 1 << MAX_LOG_ADDR, "addr must be less than 2^48");
        assert!(
            self.program.untrusted_memory.is_some_and(|(s, e)| addr >= s && addr < e),
            "untrusted mode must be turned on, the requested page must be in untrusted memory region",
        );

        // Here, the old page permission is kept in trace
        let page_idx = addr >> LOG_PAGE_SIZE;

        let page_prot_value = self.page_prots.entry(page_idx).or_default();
        if self.traces.is_some() && self.maybe_unconstrained.is_none() {
            unsafe {
                self.traces.as_mut().unwrap_unchecked().extend(&[(*page_prot_value).into()]);
            }
        }

        self.page_prots.insert(page_idx, PageProtValue { timestamp: self.clk, value: val });
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
        self.page_prots.copy_on_write();

        Ok(())
    }

    fn exit_unconstrained(&mut self) {
        let unconstrained = self
            .maybe_unconstrained
            .take()
            .expect("Exit unconstrained called but no context is present, this is a bug.");
        self.registers = unconstrained.registers;
        self.pc = unconstrained.pc;
        self.clk = unconstrained.clk;
        self.memory.owned();
        self.page_prots.owned();
    }

    fn trace_hint(&mut self, addr: u64, value: Vec<u8>) {
        if self.traces.is_some() {
            self.hints.push((addr, value));
        }
    }

    fn trace_value(&mut self, value: u64) {
        if self.traces.is_some() {
            unsafe {
                self.traces
                    .as_mut()
                    .unwrap_unchecked()
                    .extend(&[MemValue { clk: u64::MAX, value }]);
            }
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

    fn get_current_clk(&self) -> u64 {
        self.clk
    }

    fn set_clk(&mut self, clk: u64) {
        self.clk = clk;
    }

    fn elf_info(&self) -> sp1_jit::ElfInfo {
        sp1_jit::ElfInfo {
            pc_base: self.program.pc_base,
            instruction_count: self.program.instructions.len(),
            untrusted_memory: self.program.untrusted_memory,
        }
    }

    fn init_addr_iter(&self) -> impl IntoIterator<Item = u64> {
        self.memory.keys()
    }

    fn page_prot_iter(&self) -> impl IntoIterator<Item = (&u64, &PageProtValue)> {
        match &self.page_prots {
            MaybeCowPageProt::Owned { page_prot } => page_prot.iter().collect::<Vec<_>>(),
            MaybeCowPageProt::Cow { .. } => {
                unreachable!("Can't iterate page prots in COW mode")
            }
        }
    }

    fn maybe_dump_profiler_data(&self) -> (Vec<(String, u64, u64)>, Vec<u64>) {
        #[cfg(feature = "profiling")]
        if let Some((ref profiler, _)) = self.profiler {
            return profiler.dump();
        }

        (self.program.function_symbols.clone(), self.program.dump_elf_stack.clone())
    }

    #[allow(unused_variables)]
    fn maybe_insert_profiler_symbols<I: Iterator<Item = (String, u64, u64)>>(&mut self, iter: I) {
        #[cfg(feature = "profiling")]
        if let Some((ref mut profiler, _)) = self.profiler {
            for (name, addr, len) in iter {
                profiler.insert(&name, addr, len);
            }
        }
    }

    #[allow(unused_variables)]
    fn maybe_delete_profiler_symbols<I: Iterator<Item = u64>>(&mut self, iter: I) {
        #[cfg(feature = "profiling")]
        if let Some((ref mut profiler, _)) = self.profiler {
            for addr in iter {
                profiler.delete(addr);
            }
        }
    }
}

impl<M: ExecutionMode> MinimalExecutor<M> {
    /// Create a new minimal executor with memory limit. This shall only be used
    /// by `sp1_core_executor_runner`.
    #[must_use]
    pub fn new_with_limit(
        program: Arc<Program>,
        _debug: bool,
        max_trace_size: Option<u64>,
        memory_limit: Option<u64>,
    ) -> Self {
        // Insert the memory image.
        let mut memory = LimitedMemory::new_owned(memory_limit);
        let pc = program.pc_start_abs;
        for (addr, value) in program.memory_image.iter() {
            memory.insert(*addr, MemValue { clk: 0, value: *value });
        }

        // Build page protection image from program.
        let page_prots: MaybeCowPageProt = program
            .page_prot_image
            .iter()
            .map(|(page_idx, prot)| (*page_idx, PageProtValue { timestamp: 0, value: *prot }))
            .collect::<hashbrown::HashMap<_, _>>()
            .into();

        let mut result = Self {
            program,
            input: VecDeque::new(),
            registers: [0; 32],
            global_clk: 0,
            clk: 1,
            pc,
            next_pc: pc,
            next_clk: 1,
            memory: Box::new(memory),
            page_prots,
            traces: None,
            max_trace_size,
            public_values_stream: Vec::new(),
            hints: Vec::new(),
            maybe_unconstrained: None,
            debug_sender: None,
            transpiler: InstructionTranspiler,
            decoded_instruction_cache: HBHashMap::new(),
            exit_code: 0,
            #[cfg(feature = "profiling")]
            profiler: None,
            #[cfg(feature = "profiling")]
            cycle_tracker_starts: HashMap::new(),
            #[cfg(feature = "profiling")]
            cycle_tracker_totals: HashMap::new(),
            #[cfg(feature = "profiling")]
            invocation_tracker: HashMap::new(),
            _mode: PhantomData,
        };
        result.maybe_setup_profiler();
        result
    }

    /// Create a new minimal executor and transpiles the program.
    #[must_use]
    pub fn new(program: Arc<Program>, debug: bool, max_trace_size: Option<u64>) -> Self {
        Self::new_with_limit(program, debug, max_trace_size, None)
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
    #[allow(unused_variables, clippy::unused_self)]
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

    /// Get the page protection record for a specific page index.
    #[must_use]
    pub fn get_page_prot_record(&self, page_idx: u64) -> Option<PageProtValue> {
        self.page_prots.get(page_idx).copied()
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
        let ptr = (&raw const *self.memory).cast::<LimitedMemory<MemValue>>().cast_mut();
        UnsafeMemory { memory: NonNull::new(ptr).unwrap() }
    }

    /// Reset the executor, to start from the beginning of the program.
    pub fn reset(&mut self) {
        let _ = std::mem::take(&mut self.input);
        todo!()
    }

    /// Common code for debug sender and profiler recording at the start of `execute_instruction`.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn maybe_debug_and_profile(&mut self) {
        if let Some(sender) = &self.debug_sender {
            sender.send(Some(self.current_state())).expect("Failed to send debug state");
        }
        #[cfg(feature = "profiling")]
        if let Some((ref mut profiler, _)) = self.profiler {
            if self.maybe_unconstrained.is_none() {
                profiler.record(self.global_clk, self.pc);
            }
        }
    }

    /// Common code for updating state after instruction execution.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn post_instruction_update(&mut self) {
        self.registers[0] = 0;
        self.pc = self.next_pc;
        self.clk = self.next_clk;
        if self.maybe_unconstrained.is_none() {
            self.global_clk = self.global_clk.wrapping_add(1);
        }
    }

    /// Check if trace buffer size has been exceeded.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn check_trace_buffer_exceeded(&self) -> bool {
        self.traces.as_ref().is_some_and(|trace| {
            trace.num_mem_reads()
                >= self.max_trace_size.expect("If traces is some, max_trace_size must be some")
        })
    }

    /// Handle special cases for syscalls after ecall execution.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn handle_ecall_special_cases(&mut self, code: SyscallCode) {
        match code {
            SyscallCode::EXIT_UNCONSTRAINED => {
                self.next_pc = self.pc.wrapping_add(PC_INC);
                self.next_clk = self.clk.wrapping_add(CLK_INC + 256);
            }
            SyscallCode::HALT => {
                self.next_pc = HALT_PC;
            }
            _ => {}
        }
    }

    /// Execute a load instruction (no permission checking).
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn execute_load(&mut self, instruction: &Instruction) {
        let (rd, rs1, imm_offset) = instruction.i_type();
        let base = self.registers[rs1 as usize];
        let addr = base.wrapping_add(imm_offset);
        let aligned_addr = addr & !0b111;

        let mem_value = self.memory.get_mut(aligned_addr);
        if self.traces.is_some() && self.maybe_unconstrained.is_none() {
            unsafe {
                self.traces.as_mut().unwrap_unchecked().extend(&[*mem_value]);
            }
        }

        mem_value.clk = self.clk + 1;
        let value = mem_value.value;

        self.registers[rd as usize] = load_value(instruction.opcode, addr, value);
    }

    /// When we store, we need to track the previous value at the address
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn execute_store(&mut self, instruction: &Instruction) {
        let (rs1, rs2, imm_offset) = instruction.s_type();
        let src = self.registers[rs1 as usize];
        let base = self.registers[rs2 as usize];
        let addr = base.wrapping_add(imm_offset);
        let aligned_addr = addr & !0b111;

        let last_value = self.mem_read_untracked(aligned_addr);
        let value = store_value(instruction.opcode, src, addr, last_value);

        let mem_value = self.memory.get_mut(aligned_addr);
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
    fn execute_jump(&mut self, instruction: &Instruction) {
        match instruction.opcode {
            Opcode::JAL => {
                let (rd, imm_offset) = instruction.j_type();
                let imm_offset_se = sign_extend_imm(imm_offset, 21);
                let pc = self.pc;
                self.next_pc = ((pc as i64).wrapping_add(imm_offset_se)) as u64;
                self.registers[rd as usize] = pc.wrapping_add(4);
            }
            Opcode::JALR => {
                let (rd, rs1, imm_offset) = instruction.i_type();
                let base = self.registers[rs1 as usize] as i64;

                let imm_offset_se = sign_extend_imm(imm_offset, 12);
                self.registers[rd as usize] = self.pc.wrapping_add(PC_INC);
                // Calculate next PC: (rs1 + imm) & ~1
                self.next_pc = (base.wrapping_add(imm_offset_se) as u64) & !1_u64;
            }
            _ => unreachable!("Invalid opcode for `execute_jump`: {:?}", instruction.opcode),
        }
    }

    /// Execute a branch instruction.
    fn execute_branch(&mut self, instruction: &Instruction) {
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
            self.next_pc = self.pc.wrapping_add(imm_offset);
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

    fn mem_read_untracked(&self, addr: u64) -> u64 {
        let mem_value = self.memory.get(addr).copied().unwrap_or_default();
        mem_value.value
    }

    /// Read page protection and trace it. Returns the protection bits.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn pr(&mut self, addr: u64, clk_bump: u64) -> u8 {
        let page_prot_value =
            self.page_prots.entry(addr / sp1_primitives::consts::PAGE_SIZE as u64).or_default();

        if self.traces.is_some() && self.maybe_unconstrained.is_none() {
            unsafe {
                self.traces.as_mut().unwrap_unchecked().extend(&[(*page_prot_value).into()]);
            }
        }

        page_prot_value.timestamp = self.clk + clk_bump;
        page_prot_value.value
    }

    /// Check page protection for a single address.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn prot_check(&mut self, addr: u64, prot_bitmap: u8, clk_bump: u64) -> Result<(), Interrupt> {
        let prot = self.pr(addr, clk_bump);
        if (prot_bitmap & PROT_EXEC) != 0 && (prot & PROT_EXEC) == 0 {
            return Err(Interrupt { code: PROT_FAILURE_EXEC });
        }
        if (prot_bitmap & PROT_READ) != 0 && (prot & PROT_READ) == 0 {
            return Err(Interrupt { code: PROT_FAILURE_READ });
        }
        if (prot_bitmap & PROT_WRITE) != 0 && (prot & PROT_WRITE) == 0 {
            return Err(Interrupt { code: PROT_FAILURE_WRITE });
        }
        Ok(())
    }
}

macro_rules! impl_execute_chunk {
    () => {
        /// Execute the program. Returning a trace chunk if the program has not completed.
        #[inline]
        pub fn execute_chunk(&mut self) -> Option<TraceChunkRaw> {
            self.try_execute_chunk().expect("execute chunk")
        }

        /// Execute the program. Returning a trace chunk if the program has not completed.
        #[allow(clippy::redundant_closure_for_method_calls)]
        pub fn try_execute_chunk(&mut self) -> Result<Option<TraceChunkRaw>, ExecutionError> {
            if self.memory.has_last_error() {
                return Err(self.memory.last_error());
            }

            if self.is_done() {
                return Ok(None);
            }

            let capacity = trace_capacity(self.max_trace_size);
            if capacity > 0 {
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

            while !self.execute_instruction() {
                if self.memory.has_last_error() {
                    return Err(self.memory.last_error());
                }
            }

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
                    traces.write_global_clk_end(self.global_clk);
                }
            }

            let traces = std::mem::take(&mut self.traces);

            Ok(traces.map(|trace| unsafe { TraceChunkRaw::new(trace.into()) }))
        }
    };
}

// SupervisorMode: simple execution without permission checks.
impl MinimalExecutor<crate::SupervisorMode> {
    impl_execute_chunk!();
    fn execute_instruction(&mut self) -> bool {
        let program = self.program.clone();
        let instruction = program.fetch(self.pc).unwrap();
        self.maybe_debug_and_profile();

        self.next_pc = self.pc.wrapping_add(PC_INC);
        self.next_clk = self.clk.wrapping_add(CLK_INC);

        if instruction.is_alu_instruction() {
            self.execute_alu(instruction);
        } else if instruction.is_memory_load_instruction() {
            self.execute_load(instruction);
        } else if instruction.is_memory_store_instruction() {
            self.execute_store(instruction);
        } else if instruction.is_branch_instruction() {
            self.execute_branch(instruction);
        } else if instruction.is_jump_instruction() {
            self.execute_jump(instruction);
        } else if instruction.is_utype_instruction() {
            self.execute_utype(instruction);
        } else if instruction.is_ecall_instruction() {
            self.execute_ecall(instruction);
        } else {
            unreachable!("Invalid opcode for `execute_instruction`: {:?}", instruction.opcode)
        }

        self.post_instruction_update();
        self.is_done() || self.check_trace_buffer_exceeded()
    }

    #[inline]
    fn execute_ecall(&mut self, instruction: &Instruction) {
        let opcode = instruction.opcode;
        assert!(instruction.is_ecall_instruction(), "Invalid ecall opcode: {opcode:?}");

        let code = SyscallCode::from_u32(self.registers[Register::X5 as usize] as u32);

        if code != SyscallCode::EXIT_UNCONSTRAINED {
            self.next_clk = self.next_clk.wrapping_add(256);
        }

        self.registers[Register::X5 as usize] =
            ecall_handler(self, code).expect("ecall returned interrupt in SupervisorMode");
        self.handle_ecall_special_cases(code);
    }
}

// UserMode: execution with permission checks and trap handling.
impl MinimalExecutor<crate::UserMode> {
    impl_execute_chunk!();

    /// Fetch an instruction. For trusted code, this reads from the program.
    /// For untrusted code (PC not in program range), reads from memory and decodes.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn fetch(&mut self) -> Result<Option<Instruction>, Interrupt> {
        let instruction = self.program.fetch(self.pc);
        Ok(if let Some(instruction) = instruction {
            Some(*instruction)
        } else {
            // Instruction is not in the trusted program — fetch from memory.
            let aligned_pc = self.pc & !0b111;

            // Check read + execute permission on the page containing this instruction.
            self.prot_check(aligned_pc, PROT_READ | PROT_EXEC, 0)?;

            // Read the memory value and trace it.
            let mem_value = self.memory.get_mut(aligned_pc);
            if self.traces.is_some() && self.maybe_unconstrained.is_none() {
                unsafe {
                    self.traces.as_mut().unwrap_unchecked().extend(&[*mem_value]);
                }
            }
            mem_value.clk = self.clk;
            let memory_value = mem_value.value;

            // Extract the 32-bit instruction from the 64-bit memory word.
            let aligned_offset = self.pc - aligned_pc;
            assert!(
                self.pc.is_multiple_of(4),
                "PC must be aligned to 4 bytes (pc=0x{:x})",
                self.pc
            );
            let instruction_value: u32 =
                (memory_value >> (aligned_offset * 8) & 0xffff_ffff).try_into().unwrap();

            // Decode the instruction (with caching).
            let instruction = if let Some(cached) =
                self.decoded_instruction_cache.get(&instruction_value)
            {
                *cached
            } else {
                let decoded = process_instruction(&mut self.transpiler, instruction_value).unwrap();
                self.decoded_instruction_cache.insert(instruction_value, decoded);
                decoded
            };
            Some(instruction)
        })
    }

    fn execute_instruction(&mut self) -> bool {
        self.maybe_debug_and_profile();

        let mut interrupt = None;
        self.next_pc = self.pc.wrapping_add(PC_INC);
        self.next_clk = self.clk.wrapping_add(CLK_INC);

        let original_clk = self.clk;

        match self.fetch() {
            Ok(None) => panic!("Unable to fetch instruction, pc=0x{:x}", self.pc),
            Ok(Some(instruction)) => {
                if instruction.is_alu_instruction() {
                    self.execute_alu(&instruction);
                } else if instruction.is_memory_load_instruction() {
                    if let Err(i) = self.execute_load_user(&instruction) {
                        interrupt = Some(i);
                    }
                } else if instruction.is_memory_store_instruction() {
                    if let Err(i) = self.execute_store_user(&instruction) {
                        interrupt = Some(i);
                    }
                } else if instruction.is_branch_instruction() {
                    self.execute_branch(&instruction);
                } else if instruction.is_jump_instruction() {
                    self.execute_jump(&instruction);
                } else if instruction.is_utype_instruction() {
                    self.execute_utype(&instruction);
                } else if instruction.is_ecall_instruction() {
                    if let Err(i) = self.execute_ecall_user(&instruction) {
                        interrupt = Some(i);
                    }
                } else {
                    unreachable!(
                        "Invalid opcode for `execute_instruction`: {:?}",
                        instruction.opcode
                    )
                }
            }
            Err(i) => {
                interrupt = Some(i);
            }
        }

        if let Some(interrupt) = interrupt {
            let new_clk = self.clk;
            self.clk = original_clk;
            self.handle_interrupt(&interrupt);
            self.clk = new_clk;
        }

        self.post_instruction_update();
        self.is_done() || self.check_trace_buffer_exceeded()
    }

    /// Execute a load instruction with page protection checking.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn execute_load_user(&mut self, instruction: &Instruction) -> Result<(), Interrupt> {
        let (_, rs1, imm_offset) = instruction.i_type();
        let base = self.registers[rs1 as usize];
        let addr = base.wrapping_add(imm_offset);
        let aligned_addr = addr & !0b111;

        self.prot_check(aligned_addr, PROT_READ, 1)?;
        self.execute_load(instruction);
        Ok(())
    }

    /// Execute a store instruction with page protection checking.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn execute_store_user(&mut self, instruction: &Instruction) -> Result<(), Interrupt> {
        let (_, rs2, imm_offset) = instruction.s_type();
        let base = self.registers[rs2 as usize];
        let addr = base.wrapping_add(imm_offset);
        let aligned_addr = addr & !0b111;

        self.prot_check(aligned_addr, PROT_WRITE, 1)?;
        self.execute_store(instruction);
        Ok(())
    }

    /// Handle an interrupt by redirecting execution to the trap handler.
    fn handle_interrupt(&mut self, interrupt: &Interrupt) {
        if let Some(trap_context_address) = self.program.trap_context {
            self.next_pc = self.mr_without_prot(trap_context_address);
            self.mw_without_prot(trap_context_address + 8, interrupt.code);
            self.mw_without_prot(trap_context_address + 16, self.pc);
        } else {
            panic!("A memory permission failure happens at pc=0x{:x}", self.pc);
        }
    }

    #[inline]
    #[allow(clippy::unnecessary_wraps)]
    fn execute_ecall_user(&mut self, instruction: &Instruction) -> Result<(), Interrupt> {
        let opcode = instruction.opcode;
        assert!(instruction.is_ecall_instruction(), "Invalid ecall opcode: {opcode:?}");

        let code = SyscallCode::from_u32(self.registers[Register::X5 as usize] as u32);

        if code == SyscallCode::SIG_RETURN {
            let addr = self.registers[Register::X10 as usize];
            let value = self.mr_without_prot(addr);
            self.next_pc = value;
        }

        if code != SyscallCode::EXIT_UNCONSTRAINED {
            self.next_clk = self.next_clk.wrapping_add(256);
        }

        self.registers[Register::X5 as usize] = ecall_handler(self, code)?;
        self.handle_ecall_special_cases(code);
        Ok(())
    }
}

fn sign_extend_imm(value: u64, bits: u8) -> i64 {
    let shift = 64 - bits;
    ((value as i64) << shift) >> shift
}

fn load_value(opcode: Opcode, addr: u64, value: u64) -> u64 {
    match opcode {
        Opcode::LB => ((value >> ((addr % 8) * 8)) & 0xFF) as i8 as i64 as u64,
        Opcode::LH => {
            assert!(addr.is_multiple_of(2), "LH must be aligned to 2 bytes (addr=0x{addr:x})");
            ((value >> (((addr / 2) % 4) * 16)) & 0xFFFF) as i16 as i64 as u64
        }
        Opcode::LW => {
            assert!(addr.is_multiple_of(4), "LW must be aligned to 4 bytes (addr=0x{addr:x})");
            ((value >> (((addr / 4) % 2) * 32)) & 0xFFFFFFFF) as i32 as u64
        }
        Opcode::LBU => ((value >> ((addr % 8) * 8)) & 0xFF) as u8 as u64,
        Opcode::LHU => {
            assert!(addr.is_multiple_of(2), "LHU must be aligned to 2 bytes (addr=0x{addr:x})");
            ((value >> (((addr / 2) % 4) * 16)) & 0xFFFF) as u16 as u64
        }
        Opcode::LWU => {
            assert!(addr.is_multiple_of(4), "LWU must be aligned to 4 bytes (addr=0x{addr:x})");
            (value >> (((addr / 4) % 2) * 32)) & 0xFFFFFFFF
        }
        Opcode::LD => {
            assert!(addr.is_multiple_of(8), "LD must be aligned to 8 bytes (addr=0x{addr:x})");
            value
        }
        _ => unreachable!("Invalid opcode for `load_value`: {:?}", opcode),
    }
}

#[allow(clippy::inline_always)]
#[inline(always)]
fn store_value(opcode: Opcode, src: u64, addr: u64, last_value: u64) -> u64 {
    match opcode {
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
        Opcode::SD => {
            assert!(addr.is_multiple_of(8), "SD must be aligned to 8 bytes");
            src
        }
        _ => unreachable!(),
    }
}

impl<M: ExecutionMode> DebugState for MinimalExecutor<M> {
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
    memory: NonNull<LimitedMemory<MemValue>>,
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
        memory.get_raw(addr).copied().unwrap_or_default()
    }
}
