use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    MemoryLocalEvent, PageProtLocalEvent, PageProtRecord,
};

/// Blake3 Compress Page Prot Access.
///
/// Tracks page protection access records for the Blake3 compress operation.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct Blake3CompressPageProtAccess {
    /// Reading initial state prot records.
    pub state_read_page_prot_records: Vec<PageProtRecord>,
    /// Reading message prot records.
    pub msg_read_page_prot_records: Vec<PageProtRecord>,
    /// Writing final state prot records.
    pub state_write_page_prot_records: Vec<PageProtRecord>,
}

/// Blake3 Compress Event.
///
/// This event is emitted when a Blake3 inner compress operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct Blake3CompressEvent {
    /// The clock cycle.
    pub clk: u64,
    /// Pointer to the 16-word state array (in/out).
    pub state_ptr: u64,
    /// Pointer to the 16-word message array (read-only).
    pub msg_ptr: u64,
    /// The initial state (before compression).
    pub state_in: [u32; 16],
    /// The final state (after compression).
    pub state_out: [u32; 16],
    /// The message words.
    pub msg: [u32; 16],
    /// Memory read records for the initial state.
    pub state_read_records: [MemoryReadRecord; 16],
    /// Memory read records for the message.
    pub msg_read_records: [MemoryReadRecord; 16],
    /// Memory write records for the final state.
    pub state_write_records: [MemoryWriteRecord; 16],
    /// Local memory access events.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// Page protection access records.
    pub page_prot_access: Blake3CompressPageProtAccess,
    /// Local page protection access events.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}
