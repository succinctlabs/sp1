use serde::{Deserialize, Serialize};

use crate::events::{MemoryReadRecord, MemoryWriteRecord};

/// Memory Copy Event.
///
/// This object encapsulated the information needed to prove a memory copy operation. This includes
/// its shard, channel, opcode, operands, and other relevant information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemCopyEvent {
    /// The lookup identifer.
    pub lookup_id: u128,
    /// The shard number.
    pub shard: u32,
    /// The channel number.
    pub channel: u8,
    /// The clock cycle.
    pub clk: u32,
    /// The source pointer.
    pub src_ptr: u32,
    /// The destination pointer.
    pub dst_ptr: u32,
    /// The number of bytes to copy.
    pub nbytes: u8,
    /// The read records.
    pub read_records: Vec<MemoryReadRecord>,
    /// The write records.
    pub write_records: Vec<MemoryWriteRecord>,
    // TODO maybe a flag for if we need an extra r/w for extra bytes at the dst?
}
