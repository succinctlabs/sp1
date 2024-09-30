use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    LookupId,
};

/// SHA-256 Compress Event.
///
/// This event is emitted when a SHA-256 compress operation is performed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShaCompressEvent {
    /// The lookup identifer.   
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The channel number.
    pub channel: u8,
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
}
