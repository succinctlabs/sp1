use serde::{Deserialize, Serialize};

use crate::syscalls::SyscallCode;

use super::MemoryRecordEnum;

/// Syscall Event.
///
/// This object encapsulated the information needed to prove a syscall invocation from the CPU
/// table. This includes its shard, clk, syscall id, arguments, other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct SyscallEvent {
    /// The program counter.
    pub pc: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The `op_a` memory record.
    pub a_record: Option<MemoryRecordEnum>,
    /// The syscall code.
    pub syscall_code: SyscallCode,
    /// The syscall id.
    pub syscall_id: u32,
    /// The first operand value (`op_b`).
    pub arg1: u32,
    /// The second operand value (`op_c`).
    pub arg2: u32,
    /// The nonce for the syscall.
    pub nonce: u32,
}
