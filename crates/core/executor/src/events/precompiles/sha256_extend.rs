use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    LookupId, MemoryLocalEvent,
};

/// SHA-256 Extend Event.
///
/// This event is emitted when a SHA-256 extend operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ShaExtendEvent {
    /// The lookup identifier.
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the word.
    pub w_ptr: u32,
    /// The memory reads of w[i-15].
    pub w_i_minus_15_reads: Vec<MemoryReadRecord>,
    /// The memory reads of w[i-2].
    pub w_i_minus_2_reads: Vec<MemoryReadRecord>,
    /// The memory reads of w[i-16].
    pub w_i_minus_16_reads: Vec<MemoryReadRecord>,
    /// The memory reads of w[i-7].
    pub w_i_minus_7_reads: Vec<MemoryReadRecord>,
    /// The memory writes of w[i].
    pub w_i_writes: Vec<MemoryWriteRecord>,
    /// The local memory accesses.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
