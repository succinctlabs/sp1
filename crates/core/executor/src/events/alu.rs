use serde::{Deserialize, Serialize};

use crate::Opcode;

use super::{create_alu_lookups, LookupId};

/// Arithmetic Logic Unit (ALU) Event.
///
/// This object encapsulated the information needed to prove an ALU operation. This includes its
/// shard, channel, opcode, operands, and other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AluEvent {
    /// The lookup identifer.
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The channel number.
    pub channel: u8,
    /// The clock cycle.
    pub clk: u32,
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

impl AluEvent {
    /// Create a new [`AluEvent`].
    #[must_use]
    pub fn new(shard: u32, channel: u8, clk: u32, opcode: Opcode, a: u32, b: u32, c: u32) -> Self {
        Self {
            lookup_id: LookupId::default(),
            shard,
            channel,
            clk,
            opcode,
            a,
            b,
            c,
            sub_lookups: create_alu_lookups(),
        }
    }
}
