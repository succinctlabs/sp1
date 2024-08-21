use serde::{Deserialize, Serialize};

use crate::events::{MemoryReadRecord, MemoryWriteRecord};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemCopyEvent {
    pub lookup_id: u128,
    pub shard: u32,
    pub channel: u8,
    pub clk: u32,
    pub src_ptr: u32,
    pub dst_ptr: u32,
    pub read_records: Vec<MemoryReadRecord>,
    pub write_records: Vec<MemoryWriteRecord>,
}
