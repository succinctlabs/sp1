use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    MemoryLocalEvent,
};

/// blake2f Compress Event.
///
/// This event is emitted when a blake2f compress operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Blake2fCompressEvent {
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// Pointer to input
    pub base_ptr: u32,
    /// Rounds
    pub rounds: u32,
    /// State
    pub h: [u64; 8],
    /// Message
    pub m: [u64; 16],
    /// Offset 1
    pub t0: u64,
    /// Offset 2
    pub t1: u64,
    /// Final flag
    pub f: bool,
    /// Compression output
    pub result: [u64; 8],
    /// Read records
    pub read_records: Vec<MemoryReadRecord>, // (1 + 16 + 32 + 4 + 1) = 54 u32 reads
    /// Write records
    pub write_records: Vec<MemoryWriteRecord>, // 8 * 64-bit words
    /// Local memory accesses.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
