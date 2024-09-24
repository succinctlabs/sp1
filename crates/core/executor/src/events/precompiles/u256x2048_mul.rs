use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    LookupId,
};

/// Uint256 Mul Event.
///
/// This event is emitted when a uint256 mul operation is performed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct U256xU2048MulEvent {
    /// The lookup identifer.
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The channel number.
    pub channel: u8,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the a value.
    pub a_ptr: u32,
    /// The x value as a list of words.
    pub a: Vec<u32>,
    /// The pointer to the b value.
    pub b_ptr: u32,
    /// The b value as a list of words.
    pub b: Vec<u32>,
    /// The pointer to the lo value.
    pub lo_ptr: u32,
    pub lo_ptr_memory: MemoryReadRecord,
    /// The lo value as a list of words.
    pub lo: Vec<u32>,
    /// The pointer to the hi value.
    pub hi_ptr: u32,
    pub hi_ptr_memory: MemoryReadRecord,
    /// The hi value as a list of words.
    pub hi: Vec<u32>,
    /// The memory records for the a value.
    pub a_memory_records: Vec<MemoryReadRecord>,
    /// The memory records for the b value.
    pub b_memory_records: Vec<MemoryReadRecord>,
    /// The memory records for lo.
    pub lo_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for hi.
    pub hi_memory_records: Vec<MemoryWriteRecord>,
}
