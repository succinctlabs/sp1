use serde::{Deserialize, Serialize};

use crate::events::{LookupId, MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord};

/// This is an arithmetic operation for emulating modular arithmetic.
#[derive(Default, PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
pub enum FieldOperation {
    /// Addition.
    #[default]
    Add,
    /// Multiplication.
    Mul,
    /// Subtraction.
    Sub,
    /// Division.
    Div,
}

/// Emulated Field Operation Events.
///
/// This event is emitted when an emulated field operation is performed on the input operands.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct FpOpEvent {
    /// The lookup id.
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the x operand.
    pub x_ptr: u32,
    /// The x operand.
    pub x: Vec<u32>,
    /// The pointer to the y operand.
    pub y_ptr: u32,
    /// The y operand.
    pub y: Vec<u32>,
    /// The operation to perform.
    pub op: FieldOperation,
    /// The memory records for the x operand.
    pub x_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for the y operand.
    pub y_memory_records: Vec<MemoryReadRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

/// Emulated Degree 2 Field Addition/Subtraction Events.
///
/// This event is emitted when an emulated degree 2 field operation is performed on the input
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Fp2AddSubEvent {
    /// The lookup id.
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The operation to perform.
    pub op: FieldOperation,
    /// The pointer to the x operand.
    pub x_ptr: u32,
    /// The x operand.
    pub x: Vec<u32>,
    /// The pointer to the y operand.
    pub y_ptr: u32,
    /// The y operand.
    pub y: Vec<u32>,
    /// The memory records for the x operand.
    pub x_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for the y operand.
    pub y_memory_records: Vec<MemoryReadRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

/// Emulated Degree 2 Field Multiplication Events.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Fp2MulEvent {
    /// The lookup id.
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the x operand.
    pub x_ptr: u32,
    /// The x operand.
    pub x: Vec<u32>,
    /// The pointer to the y operand.
    pub y_ptr: u32,
    /// The y operand.
    pub y: Vec<u32>,
    /// The memory records for the x operand.
    pub x_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for the y operand.
    pub y_memory_records: Vec<MemoryReadRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
