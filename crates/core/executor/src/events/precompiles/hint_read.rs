use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::events::memory::MemoryWriteRecord;

/// `HintRead` Event.
///
/// Emitted by the `HINT_READ` syscall, which performs an arbitrary write of
/// `len_bytes.div_ceil(8)` words starting at `ptr`.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct HintReadEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The pointer that the hint is written to.
    pub ptr: u64,
    /// The number of bytes requested by the hint.
    pub len_bytes: u64,
    /// The memory write records, one per written word (`len_bytes.div_ceil(8)` of them).
    pub memory_records: Vec<MemoryWriteRecord>,
}
