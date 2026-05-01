use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::{SyscallCode, TrapError, TrapResult};

use super::MemoryReadRecord;

/// Syscall Event.
///
/// This object encapsulated the information needed to prove a syscall invocation from the CPU
/// table. This includes its shard, clk, syscall id, arguments, other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, DeepSizeOf)]
#[repr(C)]
pub struct SyscallEvent {
    /// The program counter.
    pub pc: u64,
    /// The next program counter.
    pub next_pc: u64,
    /// The clock cycle.
    pub clk: u64,
    /// Whether this syscall should be sent.
    pub should_send: bool,
    /// The syscall code.
    pub syscall_code: SyscallCode,
    /// The syscall id.
    pub syscall_id: u32,
    /// The first operand value (`op_b`).
    pub arg1: u64,
    /// The second operand value (`op_c`).
    pub arg2: u64,
    /// The exit code.
    pub exit_code: u32,
    /// The memory record to read the next pc, if a `SIG_RETURN` is called.
    pub sig_return_pc_record: Option<MemoryReadRecord>,
    /// The trap result, if the syscall event leads to a trap.
    pub trap_result: Option<TrapResult>,
    /// The trap error, if the syscall event leads to a trap.
    pub trap_error: Option<TrapError>,
}
