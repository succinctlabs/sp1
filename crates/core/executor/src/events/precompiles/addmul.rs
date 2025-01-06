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

    /// a value as list of words
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub e: u32,

    pub a_ptr: u32,
    pub b_ptr: u32,
    pub c_ptr: u32,
    pub d_ptr: u32,
    pub e_ptr: u32,
    pub a_memory_records: MemoryReadRecord,
    pub b_memory_records: MemoryReadRecord,
    pub c_memory_records: MemoryReadRecord,
    pub d_memory_records: MemoryReadRecord,
    pub e_memory_records: MemoryWriteRecord,
    pub c_ptr_memory: MemoryReadRecord,
    pub d_ptr_memory: MemoryReadRecord,
    pub e_ptr_memory: MemoryReadRecord,

    /// Local memory access events
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
