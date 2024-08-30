use serde::{Deserialize, Serialize};

use crate::{
    events::{LookupId, MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord},
    syscalls::SyscallCode,
};

/// This is an arithmetic operation for emulating modular arithmetic.
#[derive(PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
pub enum FieldOperation {
    /// Addition.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpOpEvent {
    /// The syscall code.
    pub syscall: SyscallCode,
    /// The lookup id.
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The channel number.
    pub channel: u8,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fp2AddSubEvent {
    /// The syscall code.
    pub syscall: SyscallCode,
    /// The lookup id.
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The channel number.
    pub channel: u8,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fp2MulEvent {
    /// The syscall code.
    pub syscall: SyscallCode,
    /// The lookup id.
    pub lookup_id: LookupId,
    /// The shard number.
    pub shard: u32,
    /// The channel number.
    pub channel: u8,
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
