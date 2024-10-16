use serde::{Deserialize, Serialize};
use sp1_curves::{edwards::WORDS_FIELD_ELEMENT, COMPRESSED_POINT_BYTES, NUM_BYTES_FIELD_ELEMENT};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    LookupId, MemoryLocalEvent,
};

/// Edwards Decompress Event.
///
/// This event is emitted when an edwards decompression operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct EdDecompressEvent {
    /// The lookup identifier.
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the point.
    pub ptr: u32,
    /// The sign bit of the point.
    pub sign: bool,
    /// The comprssed y coordinate as a list of bytes.
    pub y_bytes: [u8; COMPRESSED_POINT_BYTES],
    /// The decompressed x coordinate as a list of bytes.
    pub decompressed_x_bytes: [u8; NUM_BYTES_FIELD_ELEMENT],
    /// The memory records for the x coordinate.
    pub x_memory_records: [MemoryWriteRecord; WORDS_FIELD_ELEMENT],
    /// The memory records for the y coordinate.
    pub y_memory_records: [MemoryReadRecord; WORDS_FIELD_ELEMENT],
    /// The local memory access events.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
