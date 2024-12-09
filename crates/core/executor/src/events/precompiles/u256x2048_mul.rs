use serde::{Deserialize, Serialize};

use crate::events::memory::{MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord};

/// `U256xU2048` Mul Event.
///
/// This event is emitted when a `U256xU2048` mul operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct U256xU2048MulEvent {
    /// The shard number.
    pub shard: u32,
    /// The channel number.
    pub clk: u32,
    /// The pointer to the a value.
    pub a_ptr: u32,
    /// The a value as a list of words.
    pub a: Vec<u32>,
    /// The pointer to the b value.
    pub b_ptr: u32,
    /// The b value as a list of words.
    pub b: Vec<u32>,
    /// The pointer to the lo value.
    pub lo_ptr: u32,
    /// The memory record for the pointer to the lo value.
    pub lo_ptr_memory: MemoryReadRecord,
    /// The lo value as a list of words.
    pub lo: Vec<u32>,
    /// The pointer to the hi value.
    pub hi_ptr: u32,
    /// The memory record for the pointer to the hi value.
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
    /// The local memory access events.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
