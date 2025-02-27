use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    MemoryLocalEvent,
};

/// `inner_prouduct` Event.
///
/// This event is emitted when a `inner_product` mul is performed.
use serde::{Deserialize, Serialize};
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct InnerProductEvent {
    /// Shard number
    pub shard: u32,
    /// Clock cycle
    pub clk: u32,

    /// The pointer to the a value
    pub a_ptr: u32,
    /// The a value as a list of words
    pub a: Vec<u32>,
    /// The pointer to the b value
    pub b_ptr: u32,
    /// The b value as a list of words
    pub b: Vec<u32>,

    /// Memory record for reading length of first vector
    pub a_len_memory: MemoryReadRecord,
    /// Memory record for reading length of second vector
    pub b_len_memory: MemoryReadRecord,

    /// Memory records for reading first vector
    pub a_memory_records: Vec<MemoryReadRecord>,
    /// Memory records for reading second vector
    pub b_memory_records: Vec<MemoryReadRecord>,

    /// The computed inner product result
    pub result: u32,
    /// Memory record for writing result
    pub result_memory_records: MemoryWriteRecord,

    /// All local memory accesses during execution
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
