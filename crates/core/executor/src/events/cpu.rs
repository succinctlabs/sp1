use serde::{Deserialize, Serialize};

use super::memory::MemoryRecordEnum;

/// CPU Event.
///
/// This object encapsulates the information needed to prove a CPU operation. This includes its
/// shard, opcode, operands, and other relevant information.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct CpuEvent {
    /// The clock cycle.
    pub clk: u32,
    /// The program counter.
    pub pc: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// The first operand.
    pub a: u32,
    /// The first operand memory record.
    pub a_record: Option<MemoryRecordEnum>,
    /// The second operand.
    pub b: u32,
    /// The second operand memory record.
    pub b_record: Option<MemoryRecordEnum>,
    /// The third operand.
    pub c: u32,
    /// The third operand memory record.
    pub c_record: Option<MemoryRecordEnum>,
    /// The exit code.
    pub exit_code: u32,
}
