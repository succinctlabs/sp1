use serde::{Deserialize, Serialize};

use crate::events::{MemoryReadRecord, MemoryWriteRecord};

/// Airthmetic operation for emulating modular arithmetic.
#[derive(PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
pub enum FieldOperation {
    Add,
    Mul,
    Sub,
    Div,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpOpEvent {
    pub lookup_id: usize,
    pub shard: u32,
    pub channel: u8,
    pub clk: u32,
    pub x_ptr: u32,
    pub x: Vec<u32>,
    pub y_ptr: u32,
    pub y: Vec<u32>,
    pub op: FieldOperation,
    pub x_memory_records: Vec<MemoryWriteRecord>,
    pub y_memory_records: Vec<MemoryReadRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fp2AddSubEvent {
    pub lookup_id: usize,
    pub shard: u32,
    pub channel: u8,
    pub clk: u32,
    pub op: FieldOperation,
    pub x_ptr: u32,
    pub x: Vec<u32>,
    pub y_ptr: u32,
    pub y: Vec<u32>,
    pub x_memory_records: Vec<MemoryWriteRecord>,
    pub y_memory_records: Vec<MemoryReadRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fp2MulEvent {
    pub lookup_id: usize,
    pub shard: u32,
    pub channel: u8,
    pub clk: u32,
    pub x_ptr: u32,
    pub x: Vec<u32>,
    pub y_ptr: u32,
    pub y: Vec<u32>,
    pub x_memory_records: Vec<MemoryWriteRecord>,
    pub y_memory_records: Vec<MemoryReadRecord>,
}
