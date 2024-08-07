use serde::{Deserialize, Serialize};

use crate::runtime::Instruction;
use crate::runtime::MemoryRecordEnum;

/// A standard format for describing CPU operations that need to be proven.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct CpuEvent {
    /// The current shard.
    pub shard: u32,

    /// The current channel.
    pub channel: u8,

    /// The current clock.
    pub clk: u32,

    /// The current program counter.
    pub pc: u32,

    /// The value of the next instruction's program counter. This value needs to be made public for
    /// the last row of each shard.
    pub next_pc: u32,

    /// The current instruction.
    pub instruction: Instruction,

    /// The first operand.
    pub a: u32,

    /// The memory access record for the first operand.
    pub a_record: Option<MemoryRecordEnum>,

    /// The second operand.
    pub b: u32,

    /// The memory access record for the second operand.
    pub b_record: Option<MemoryRecordEnum>,

    /// The third operand.
    pub c: u32,

    /// The memory access record for the third operand.
    pub c_record: Option<MemoryRecordEnum>,

    /// The memory value we potentially may access.
    pub memory: Option<u32>,

    /// The memory access record for the memory value.
    pub memory_record: Option<MemoryRecordEnum>,

    /// Exit code called with halt.
    pub exit_code: u32,

    pub alu_lookup_id: u128,
    pub syscall_lookup_id: u128,
    pub memory_add_lookup_id: u128,
    pub memory_sub_lookup_id: u128,
    pub branch_gt_lookup_id: u128,
    pub branch_lt_lookup_id: u128,
    pub branch_add_lookup_id: u128,
    pub jump_jal_lookup_id: u128,
    pub jump_jalr_lookup_id: u128,
    pub auipc_lookup_id: u128,
}
