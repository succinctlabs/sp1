use serde::{Deserialize, Serialize};

use crate::Opcode;

use super::{create_random_lookup_ids, LookupId, MemoryRecordEnum};

/// Instruction Event.
///
/// This object encapsulated the information needed to prove a RISC-V operation. This includes its
/// pc, opcode, operands, and other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct InstrEvent {
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
    /// Whether the first operand is register 0.
    pub op_a_0: bool,
    /// The memory access record for memory operations.
    pub mem_access: Option<MemoryRecordEnum>,
    /// The result of the operation in the format of [``LookupId``; 6]
    pub sub_lookups: [LookupId; 6],
    /// The memory add lookup id.
    pub memory_add_lookup_id: LookupId,
    /// The memory sub lookup id.
    pub memory_sub_lookup_id: LookupId,
}

impl InstrEvent {
    /// Create a new [`InstrEvent`].
    #[must_use]
    pub fn new(
        pc: u32,
        opcode: Opcode,
        a: u32,
        b: u32,
        c: u32,
        op_a_0: bool,
        mem_access: Option<MemoryRecordEnum>,
        memory_add_lookup_id: LookupId,
        memory_sub_lookup_id: LookupId,
    ) -> Self {
        Self {
            pc,
            lookup_id: LookupId::default(),
            opcode,
            a,
            b,
            c,
            op_a_0,
            mem_access,
            sub_lookups: create_random_lookup_ids(),
            memory_add_lookup_id,
            memory_sub_lookup_id,
        }
    }
}
