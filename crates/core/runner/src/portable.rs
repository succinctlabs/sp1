#[cfg(feature = "profiling")]
use hashbrown::HashMap;
use sp1_core_executor::{ExecutionError, MinimalExecutor, Program, UnsafeMemory};
use sp1_jit::{MemValue, TraceChunkRaw};
use std::sync::Arc;

/// Minimal trace portable executor that caps memory entries
pub struct MinimalExecutorRunner {
    inner: MinimalExecutor,
}

impl MinimalExecutorRunner {
    /// Create a new minimal executor and transpile the program.
    ///
    /// # Arguments
    ///
    /// * `program` - The program to execute.
    /// * `is_debug` - Whether to compile the program with debugging.
    /// * `max_trace_size` - The maximum trace size in terms of [`MemValue`]s. If not set tracing
    ///   will be disabled.
    /// * `memory_limit` - The memory limit bytes. If not set, the default value(24 GB) will be used.
    #[must_use]
    #[inline]
    pub fn new(
        program: Arc<Program>,
        is_debug: bool,
        max_trace_size: Option<u64>,
        memory_limit: Option<u64>,
    ) -> Self {
        let memory_limit = memory_limit.unwrap_or(crate::DEFAULT_MEMORY_LIMIT);
        Self {
            inner: MinimalExecutor::new_with_limit(
                program,
                is_debug,
                max_trace_size,
                Some(memory_limit),
            ),
        }
    }

    /// Create a new minimal executor with no tracing or debugging.
    #[must_use]
    #[inline]
    pub fn simple(program: Arc<Program>) -> Self {
        Self::new(program, false, None, None)
    }

    /// Create a new minimal executor with tracing.
    ///
    /// # Arguments
    ///
    /// * `program` - The program to execute.
    /// * `max_trace_size` - The maximum trace size in terms of [`MemValue`]s. If not set, it will
    ///   be set to 2 gb worth of memory events.
    #[must_use]
    #[inline]
    pub fn tracing(program: Arc<Program>, max_trace_size: u64) -> Self {
        Self::new(program, false, Some(max_trace_size), None)
    }

    /// Create a new minimal executor with debugging.
    #[must_use]
    #[inline]
    pub fn debug(program: Arc<Program>) -> Self {
        Self::new(program, true, None, None)
    }

    /// Add input to the executor.
    #[inline]
    pub fn with_input(&mut self, input: &[u8]) {
        self.inner.with_input(input);
    }

    /// Execute the program. Returning a trace chunk if the program has not completed.
    #[inline]
    pub fn execute_chunk(&mut self) -> Option<TraceChunkRaw> {
        self.inner.execute_chunk()
    }

    /// Execute the program. Returning a trace chunk if the program has not completed.
    #[inline]
    pub fn try_execute_chunk(&mut self) -> Result<Option<TraceChunkRaw>, ExecutionError> {
        self.inner.try_execute_chunk()
    }

    /// Get the registers of the JIT function.
    #[must_use]
    #[inline]
    pub fn registers(&self) -> [u64; 32] {
        self.inner.registers()
    }

    /// Get the program counter of the JIT function.
    #[must_use]
    #[inline]
    pub fn pc(&self) -> u64 {
        self.inner.pc()
    }

    /// Check if the program has halted.
    #[must_use]
    #[inline]
    pub fn is_done(&self) -> bool {
        self.inner.is_done()
    }

    /// Get the current value at an address.
    #[must_use]
    #[inline]
    pub fn get_memory_value(&self, addr: u64) -> MemValue {
        self.inner.get_memory_value(addr)
    }

    /// Get the program of the JIT function.
    #[must_use]
    #[inline]
    pub fn program(&self) -> Arc<Program> {
        self.inner.program()
    }

    /// Get the current clock of the JIT function.
    ///
    /// This clock is incremented by 8 or 256 depending on the instruction.
    #[must_use]
    #[inline]
    pub fn clk(&self) -> u64 {
        self.inner.clk()
    }

    /// Get the global clock of the JIT function.
    ///
    /// This clock is incremented by 1 per instruction.
    #[must_use]
    #[inline]
    pub fn global_clk(&self) -> u64 {
        self.inner.global_clk()
    }

    /// Get the exit code of the JIT function.
    #[must_use]
    #[inline]
    pub fn exit_code(&self) -> u32 {
        self.inner.exit_code()
    }

    /// Get the public values stream of the JIT function.
    #[must_use]
    #[inline]
    pub fn public_values_stream(&self) -> &Vec<u8> {
        self.inner.public_values_stream()
    }

    /// Consume self, and return the public values stream.
    #[must_use]
    #[inline]
    pub fn into_public_values_stream(self) -> Vec<u8> {
        self.inner.into_public_values_stream()
    }

    /// Get the hints of the JIT function.
    #[must_use]
    #[inline]
    pub fn hints(&self) -> &[(u64, Vec<u8>)] {
        self.inner.hints()
    }

    /// Get the lengths of all the hints.
    #[must_use]
    #[inline]
    pub fn hint_lens(&self) -> Vec<usize> {
        self.inner.hint_lens()
    }

    /// Get an unsafe memory view of the JIT function.
    ///
    /// This allows reading without lifetime and mutability constraints.
    #[must_use]
    #[allow(clippy::cast_ptr_alignment)]
    #[inline]
    pub fn unsafe_memory(&self) -> UnsafeMemory {
        self.inner.unsafe_memory()
    }

    #[inline]
    pub fn reset(&mut self) {
        self.inner.reset()
    }

    /// Take the cycle tracker totals, consuming them.
    #[cfg(feature = "profiling")]
    #[must_use]
    #[inline]
    pub fn take_cycle_tracker_totals(&mut self) -> HashMap<String, u64> {
        self.inner.take_cycle_tracker_totals()
    }

    /// Take the invocation tracker, consuming it.
    #[cfg(feature = "profiling")]
    #[must_use]
    #[inline]
    pub fn take_invocation_tracker(&mut self) -> HashMap<String, u64> {
        self.inner.take_invocation_tracker()
    }
}
