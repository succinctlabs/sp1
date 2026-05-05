#![allow(clippy::items_after_statements)]
use std::sync::Arc;

use crate::{Program, SupervisorMode, UserMode};
pub use arch::*;
pub use postprocess::chunked_memory_init_events;
pub use sp1_jit::{MemValue, TraceChunkRaw};

mod arch;
mod debug;
mod ecall;
mod hint;
mod postprocess;
mod precompiles;
mod write;

#[cfg(test)]
mod tests;

/// Wrapper enum to handle `MinimalExecutor` with different execution modes at runtime.
pub enum MinimalExecutorEnum {
    /// `MinimalExecutor` for `SupervisorMode`.
    Supervisor(MinimalExecutor<SupervisorMode>),
    /// `MinimalExecutor` for `UserMode`.
    User(MinimalExecutor<UserMode>),
}

impl MinimalExecutorEnum {
    /// Create a new `MinimalExecutorEnum` based on program's `enable_untrusted_programs` flag.
    #[must_use]
    pub fn new(program: Arc<Program>, debug: bool, max_trace_entries: Option<u64>) -> Self {
        if program.enable_untrusted_programs {
            Self::User(MinimalExecutor::<UserMode>::new(program, debug, max_trace_entries))
        } else {
            Self::Supervisor(MinimalExecutor::<SupervisorMode>::new(
                program,
                debug,
                max_trace_entries,
            ))
        }
    }

    /// Create a new `MinimalExecutorEnum` with memory limit (portable executor only).
    #[cfg(sp1_use_portable_executor)]
    #[must_use]
    pub fn new_with_limit(
        program: Arc<Program>,
        debug: bool,
        max_trace_size: Option<u64>,
        memory_limit: Option<u64>,
    ) -> Self {
        if program.enable_untrusted_programs {
            Self::User(MinimalExecutor::<UserMode>::new_with_limit(
                program,
                debug,
                max_trace_size,
                memory_limit,
            ))
        } else {
            Self::Supervisor(MinimalExecutor::<SupervisorMode>::new_with_limit(
                program,
                debug,
                max_trace_size,
                memory_limit,
            ))
        }
    }

    /// Create a new `MinimalExecutorEnum` with memory limit (native executor fallback — ignores limit).
    #[cfg(not(sp1_use_portable_executor))]
    #[must_use]
    pub fn new_with_limit(
        program: Arc<Program>,
        debug: bool,
        max_trace_size: Option<u64>,
        _memory_limit: Option<u64>,
    ) -> Self {
        Self::new(program, debug, max_trace_size)
    }

    /// Calls `with_input` to respective `MinimalExecutor`.
    pub fn with_input(&mut self, input: &[u8]) {
        match self {
            Self::Supervisor(e) => e.with_input(input),
            Self::User(e) => e.with_input(input),
        }
    }

    /// Calls `execute_chunk` to respective `MinimalExecutor`.
    pub fn execute_chunk(&mut self) -> Option<TraceChunkRaw> {
        match self {
            Self::Supervisor(e) => e.execute_chunk(),
            Self::User(e) => e.execute_chunk(),
        }
    }

    /// Calls `global_clk` to respective `MinimalExecutor`.
    #[must_use]
    pub fn global_clk(&self) -> u64 {
        match self {
            Self::Supervisor(e) => e.global_clk(),
            Self::User(e) => e.global_clk(),
        }
    }

    /// Calls `exit_code` to respective `MinimalExecutor`.
    #[must_use]
    pub fn exit_code(&self) -> u32 {
        match self {
            Self::Supervisor(e) => e.exit_code(),
            Self::User(e) => e.exit_code(),
        }
    }

    /// Calls `pc` to respective `MinimalExecutor`.
    #[must_use]
    pub fn pc(&self) -> u64 {
        match self {
            Self::Supervisor(e) => e.pc(),
            Self::User(e) => e.pc(),
        }
    }

    /// Calls `registers` to respective `MinimalExecutor`.
    #[must_use]
    pub fn registers(&self) -> [u64; 32] {
        match self {
            Self::Supervisor(e) => e.registers(),
            Self::User(e) => e.registers(),
        }
    }

    /// Calls `clk` to respective `MinimalExecutor`.
    #[must_use]
    pub fn clk(&self) -> u64 {
        match self {
            Self::Supervisor(e) => e.clk(),
            Self::User(e) => e.clk(),
        }
    }

    /// Calls `public_values_stream` to respective `MinimalExecutor`.
    #[must_use]
    pub fn public_values_stream(&self) -> &Vec<u8> {
        match self {
            Self::Supervisor(e) => e.public_values_stream(),
            Self::User(e) => e.public_values_stream(),
        }
    }

    /// Calls `into_public_values_stream` to respective `MinimalExecutor`.
    #[must_use]
    pub fn into_public_values_stream(self) -> Vec<u8> {
        match self {
            Self::Supervisor(e) => e.into_public_values_stream(),
            Self::User(e) => e.into_public_values_stream(),
        }
    }

    /// Calls `hints` to respective `MinimalExecutor`.
    #[must_use]
    pub fn hints(&self) -> &[(u64, Vec<u8>)] {
        match self {
            Self::Supervisor(e) => e.hints(),
            Self::User(e) => e.hints(),
        }
    }

    /// Calls `hint_lens` to respective `MinimalExecutor`.
    #[must_use]
    pub fn hint_lens(&self) -> Vec<usize> {
        match self {
            Self::Supervisor(e) => e.hint_lens(),
            Self::User(e) => e.hint_lens(),
        }
    }

    /// Calls `get_memory_value` to respective `MinimalExecutor`.
    #[must_use]
    pub fn get_memory_value(&self, addr: u64) -> MemValue {
        match self {
            Self::Supervisor(e) => e.get_memory_value(addr),
            Self::User(e) => e.get_memory_value(addr),
        }
    }

    /// Calls `is_done` to respective `MinimalExecutor`.
    #[must_use]
    pub fn is_done(&self) -> bool {
        match self {
            Self::Supervisor(e) => e.is_done(),
            Self::User(e) => e.is_done(),
        }
    }

    /// Calls `program` to respective `MinimalExecutor`.
    #[must_use]
    pub fn program(&self) -> Arc<Program> {
        match self {
            Self::Supervisor(e) => e.program(),
            Self::User(e) => e.program(),
        }
    }

    /// Calls `unsafe_memory` to respective `MinimalExecutor`.
    #[must_use]
    pub fn unsafe_memory(&self) -> UnsafeMemory {
        match self {
            Self::Supervisor(e) => e.unsafe_memory(),
            Self::User(e) => e.unsafe_memory(),
        }
    }

    /// Calls `reset` to respective `MinimalExecutor`.
    pub fn reset(&mut self) {
        match self {
            Self::Supervisor(e) => e.reset(),
            Self::User(e) => e.reset(),
        }
    }

    /// Calls `try_execute_chunk` to respective `MinimalExecutor` (portable executor only).
    #[cfg(sp1_use_portable_executor)]
    pub fn try_execute_chunk(&mut self) -> Result<Option<TraceChunkRaw>, crate::ExecutionError> {
        match self {
            Self::Supervisor(e) => e.try_execute_chunk(),
            Self::User(e) => e.try_execute_chunk(),
        }
    }

    /// Calls `try_execute_chunk` (native executor fallback — infallible).
    #[cfg(not(sp1_use_portable_executor))]
    pub fn try_execute_chunk(&mut self) -> Result<Option<TraceChunkRaw>, crate::ExecutionError> {
        Ok(self.execute_chunk())
    }

    /// Calls `get_page_prot_record` to respective `MinimalExecutor`.
    #[must_use]
    pub fn get_page_prot_record(&self, page_idx: u64) -> Option<sp1_jit::PageProtValue> {
        match self {
            Self::Supervisor(e) => e.get_page_prot_record(page_idx),
            Self::User(e) => e.get_page_prot_record(page_idx),
        }
    }

    /// Take the cycle tracker totals, consuming them.
    #[cfg(feature = "profiling")]
    #[must_use]
    pub fn take_cycle_tracker_totals(&mut self) -> hashbrown::HashMap<String, u64> {
        match self {
            Self::Supervisor(e) => e.take_cycle_tracker_totals(),
            Self::User(e) => e.take_cycle_tracker_totals(),
        }
    }

    /// Take the invocation tracker, consuming it.
    #[cfg(feature = "profiling")]
    #[must_use]
    pub fn take_invocation_tracker(&mut self) -> hashbrown::HashMap<String, u64> {
        match self {
            Self::Supervisor(e) => e.take_invocation_tracker(),
            Self::User(e) => e.take_invocation_tracker(),
        }
    }
}
