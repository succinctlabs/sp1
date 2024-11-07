use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    LookupId, MemoryLocalEvent,
};

/// SHA-256 Compress Event.
///
/// This event is emitted when a SHA-256 compress operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ShaCompressEvent {
    /// The lookup identifier.   
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the word.
    pub w_ptr: u32,
    /// The word as a list of words.
    pub h_ptr: u32,
    /// The word as a list of words.
    pub w: Vec<u32>,
    /// The word as a list of words.
    pub h: [u32; 8],
    /// The memory records for the word.
    pub h_read_records: [MemoryReadRecord; 8],
    /// The memory records for the word.
    pub w_i_read_records: Vec<MemoryReadRecord>,
    /// The memory records for the word.
    pub h_write_records: [MemoryWriteRecord; 8],
    /// The local memory accesses.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
