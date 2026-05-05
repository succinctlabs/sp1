use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryLocalEvent, MemoryWriteRecord, PageProtLocalEvent},
    MemoryReadRecord,
};

/// `SigReturnEvent` Event.
///
/// This event is emitted when a `SigReturn` operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct SigReturnEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The pointer to the input/output array.
    pub ptr: u64,
    /// The memory records for the 32 u64 words.
    pub memory_read_records: Vec<MemoryReadRecord>,
    /// The memory records for the register writes.
    pub register_write_records: Vec<MemoryWriteRecord>,
    /// The local memory access events.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// The local page prot access events.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}
