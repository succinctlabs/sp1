use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    LookupId, MemoryLocalEvent,
};

/// Uint256 Mul Event.
///
/// This event is emitted when a uint256 mul operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Uint256MulEvent {
    /// The lookup identifier.
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the x value.
    pub x_ptr: u32,
    /// The x value as a list of words.
    pub x: Vec<u32>,
    /// The pointer to the y value.
    pub y_ptr: u32,
    /// The y value as a list of words.
    pub y: Vec<u32>,
    /// The modulus as a list of words.
    pub modulus: Vec<u32>,
    /// The memory records for the x value.
    pub x_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for the y value.
    pub y_memory_records: Vec<MemoryReadRecord>,
    /// The memory records for the modulus.
    pub modulus_memory_records: Vec<MemoryReadRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
