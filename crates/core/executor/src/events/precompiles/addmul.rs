use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    LookupId, MemoryLocalEvent,
};

/// AddMulEvent.
///
/// This event is emitted when a a*b + c*d operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct AddMulEvent {
    /// Lookup identifier
    pub lookup_id: LookupId,
    /// Shard number
    pub shard: u32,
    /// Clock cycle
    pub clk: u32,

    /// Pointer to a value
    pub a_ptr: u32,
    /// a value as list of words
    pub a: Vec<u32>,
    /// Memory records for a
    pub a_memory_records: Vec<MemoryReadRecord>,

    /// Pointer to b value
    pub b_ptr: u32,
    /// b value as list of words
    pub b: Vec<u32>,
    /// Memory records for b
    pub b_memory_records: Vec<MemoryReadRecord>,

    /// Pointer to c value
    pub c_ptr: u32,
    /// c value as list of words
    pub c: Vec<u32>,
    /// Memory records for c
    pub c_memory_records: Vec<MemoryReadRecord>,

    /// Pointer to d value
    pub d_ptr: u32,
    /// d value as list of words
    pub d: Vec<u32>,
    /// Memory records for d
    pub d_memory_records: Vec<MemoryReadRecord>,

    /// Memory records for result (written back to a_ptr)
    pub result_memory_records: Vec<MemoryWriteRecord>,

    /// Local memory access events
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
