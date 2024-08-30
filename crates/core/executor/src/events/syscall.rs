use serde::{Deserialize, Serialize};

use super::LookupId;

/// Syscall Event.
///
/// This object encapsulated the information needed to prove a syscall invocation from the CPU table.
/// This includes its shard, clk, channel, syscall id, arguments, other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// The shard number.
    pub shard: u32,
    /// The channel number.
    pub channel: u8,
    /// The clock cycle.
    pub clk: u32,
    /// The lookup id.
    pub lookup_id: LookupId,
    /// The syscall id.
    pub syscall_id: u32,
    /// The first argument.
    pub arg1: u32,
    /// The second operand.
    pub arg2: u32,
}
