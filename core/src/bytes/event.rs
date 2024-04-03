use super::ByteOpcode;
use serde::{Deserialize, Serialize};

/// A byte lookup event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ByteLookupEvent {
    /// The shard number, used for byte lookup table.
    pub shard: u32,

    /// The opcode of the operation.
    pub opcode: ByteOpcode,

    /// The first output operand.
    pub a1: u32,

    /// The second output operand.
    pub a2: u32,

    /// The first input operand.
    pub b: u32,

    /// The second input operand.
    pub c: u32,
}

impl ByteLookupEvent {
    /// Creates a new `ByteLookupEvent`.
    pub fn new(shard: u32, opcode: ByteOpcode, a1: u32, a2: u32, b: u32, c: u32) -> Self {
        Self {
            shard,
            opcode,
            a1,
            a2,
            b,
            c,
        }
    }
}
