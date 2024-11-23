use serde::{Deserialize, Serialize};

use crate::Opcode;

use super::{create_random_lookup_ids, LookupId};

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
    /// The first operand.
    pub a: u32,
    /// The second operand.
    pub b: u32,
    /// The third operand.
    pub c: u32,
    /// The result of the operation in the format of [``LookupId``; 6]
    pub sub_lookups: [LookupId; 6],
}

impl InstrEvent {
    /// Create a new [`InstrEvent`].
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
