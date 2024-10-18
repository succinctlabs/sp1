use serde::{Deserialize, Serialize};

use crate::Instruction;

use super::{memory::MemoryRecordEnum, LookupId};

/// CPU Event.
///
/// This object encapsulates the information needed to prove a CPU operation. This includes its
/// shard, opcode, operands, and other relevant information.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct CpuEvent {
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The program counter.
    pub pc: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// The instruction.
    pub instruction: Instruction,
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
    /// The memory value.
    pub memory: Option<u32>,
    /// The memory record.
    pub memory_record: Option<MemoryRecordEnum>,
    /// The exit code.
    pub exit_code: u32,
    /// The ALU lookup id.
    pub alu_lookup_id: LookupId,
    /// The syscall lookup id.
    pub syscall_lookup_id: LookupId,
    /// The memory add lookup id.
    pub memory_add_lookup_id: LookupId,
    /// The memory sub lookup id.
    pub memory_sub_lookup_id: LookupId,
    /// The branch gt lookup id.
    pub branch_gt_lookup_id: LookupId,
    /// The branch lt lookup id.
    pub branch_lt_lookup_id: LookupId,
    /// The branch add lookup id.
    pub branch_add_lookup_id: LookupId,
    /// The jump jal lookup id.
    pub jump_jal_lookup_id: LookupId,
    /// The jump jalr lookup id.
    pub jump_jalr_lookup_id: LookupId,
    /// The auipc lookup id.
    pub auipc_lookup_id: LookupId,
}
