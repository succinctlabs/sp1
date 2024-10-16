use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    LookupId, MemoryLocalEvent,
};

pub(crate) const STATE_SIZE: usize = 25;

/// Keccak-256 Permutation Event.
///
/// This event is emitted when a keccak-256 permutation operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct KeccakPermuteEvent {
    /// The lookup identifier.
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pre-state as a list of u64 words.
    pub pre_state: [u64; STATE_SIZE],
    /// The post-state as a list of u64 words.
    pub post_state: [u64; STATE_SIZE],
    /// The memory records for the pre-state.
    pub state_read_records: Vec<MemoryReadRecord>,
    /// The memory records for the post-state.
    pub state_write_records: Vec<MemoryWriteRecord>,
    /// The address of the state.
    pub state_addr: u32,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
