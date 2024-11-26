use serde::{Deserialize, Serialize};

use crate::Opcode;

use super::{create_random_lookup_ids, LookupId, MemoryRecordEnum};

/// Alu Instruction Event.
///
/// This object encapsulated the information needed to prove a RISC-V ALU operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AluEvent {
    /// The program counter.
    pub pc: u32,
    /// The lookup identifier.
    pub lookup_id: LookupId,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u32,
    /// The second operand value.
    pub b: u32,
    /// The third operand value.
    pub c: u32,
    /// The result of the operation in the format of [``LookupId``; 6]
    pub sub_lookups: [LookupId; 6],
}

impl AluEvent {
    /// Create a new [`AluEvent`].
    #[must_use]
    pub fn new(pc: u32, opcode: Opcode, a: u32, b: u32, c: u32) -> Self {
        Self {
            pc,
            lookup_id: LookupId::default(),
            opcode,
            a,
            b,
            c,
            sub_lookups: create_random_lookup_ids(),
        }
    }
}

/// Memory Instruction Event.
///
/// This object encapsulated the information needed to prove a RISC-V memory operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MemInstrEvent {
    /// The shard.
    pub shard: u32,
    /// The clk.
    pub clk: u32,
    /// The program counter.
    pub pc: u32,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u32,
    /// The second operand value.
    pub b: u32,
    /// The third operand value.
    pub c: u32,
    /// Whether the first operand is register 0.
    pub op_a_0: bool,
    /// The memory access record for memory operations.
    pub mem_access: MemoryRecordEnum,
    /// The memory add lookup id.
    pub memory_add_lookup_id: LookupId,
    /// The memory sub lookup id.
    pub memory_sub_lookup_id: LookupId,
}

impl MemInstrEvent {
    /// Create a new [`MemInstrEvent`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard: u32,
        clk: u32,
        pc: u32,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        op_a_0: bool,
        mem_access: MemoryRecordEnum,
        memory_add_lookup_id: LookupId,
        memory_sub_lookup_id: LookupId,
    ) -> Self {
        Self {
            shard,
            clk,
            pc,
            opcode,
            a,
            b,
            c,
            op_a_0,
            mem_access,
            memory_add_lookup_id,
            memory_sub_lookup_id,
        }
    }
}

/// AUIPC Instruction Event.
///
/// This object encapsulated the information needed to prove a RISC-V memory operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AUIPCEvent {
    /// The program counter.
    pub pc: u32,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand value.
    pub a: u32,
    /// The second operand value.
    pub b: u32,
    /// The third operand value.
    pub c: u32,
    /// The AUIPC add lookup id.
    pub auipc_nonce: LookupId,
}

impl AUIPCEvent {
    /// Create a new [`AUIPCEvent`].
    #[must_use]
    pub fn new(pc: u32, opcode: Opcode, a: u32, b: u32, c: u32, auipc_nonce: LookupId) -> Self {
        Self { pc, opcode, a, b, c, auipc_nonce }
    }
}
