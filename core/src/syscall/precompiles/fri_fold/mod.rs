use crate::syscall::precompiles::{MemoryReadRecord, MemoryWriteRecord};

mod air;
mod columns;
mod execute;
mod trace;

#[derive(Debug, Clone)]
pub struct FriFoldEvent {
    pub clk: u32,
    pub shard: u32,

    pub input_slice_read_records: Vec<MemoryReadRecord>,
    pub input_slice_ptr: u32,
    pub output_slice_read_records: Vec<MemoryReadRecord>,
    pub output_slice_ptr: u32,

    pub ro_read_records: Vec<MemoryReadRecord>,
    pub ro_write_records: Vec<MemoryWriteRecord>,

    pub alpha_pow_read_records: Vec<MemoryReadRecord>,
    pub alpha_pow_write_records: Vec<MemoryWriteRecord>,
}

pub struct FriFoldChip {}

impl FriFoldChip {
    pub fn new() -> Self {
        Self {}
    }
}
