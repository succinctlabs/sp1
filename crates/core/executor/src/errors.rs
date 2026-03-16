//! Error types for the SP1 executor.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Opcode;

/// Errors that the executor can throw.
#[derive(Clone, Error, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecutionError {
    /// The execution failed with an invalid memory access.
    #[error("invalid memory access for opcode {0} and address {1}")]
    InvalidMemoryAccess(Opcode, u64),

    /// The address for a untrusted program instruction is not aligned to 4 bytes.
    #[error("invalid memory access for untrusted program at address {0}, not aligned to 4 bytes")]
    InvalidMemoryAccessUntrustedProgram(u64),

    /// The execution failed with an unimplemented syscall.
    #[error("unimplemented syscall {0}")]
    UnsupportedSyscall(u32),

    /// The execution failed with a breakpoint.
    #[error("breakpoint encountered")]
    Breakpoint(),

    /// The execution failed with an exceeded cycle limit.
    #[error("exceeded cycle limit of {0}")]
    ExceededCycleLimit(u64),

    /// The execution failed because the syscall was called in unconstrained mode.
    #[error("syscall called in unconstrained mode")]
    InvalidSyscallUsage(u64),

    /// The execution failed with an unimplemented feature.
    #[error("got unimplemented as opcode")]
    Unimplemented(),

    /// The program ended in unconstrained mode.
    #[error("program ended in unconstrained mode")]
    EndInUnconstrained(),

    /// The unconstrained cycle limit was exceeded.
    #[error("unconstrained cycle limit exceeded")]
    UnconstrainedCycleLimitExceeded(u64),

    /// The program ended with an unexpected status code.
    #[error("Unexpected exit code: {0}")]
    UnexpectedExitCode(u32),

    /// Page protect is off, and the instruction is not found.
    #[error("Instruction not found, page protect/ untrusted program set to off")]
    InstructionNotFound(),

    /// The sharding state is invalid.
    #[error("Running executor in non-sharding state, but got a shard boundary or trace end")]
    InvalidShardingState(),

    /// SP1 program consumes too much memory
    #[error("SP1 program consumes too much memory")]
    TooMuchMemory(),

    /// A generic error.
    #[error("{0}")]
    Other(String),
}
