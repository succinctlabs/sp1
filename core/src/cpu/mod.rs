use crate::runtime::Instruction;

pub mod air;
pub mod columns;
pub mod trace;

#[derive(Debug, Copy, Clone)]
pub struct CpuEvent {
    pub segment: u32,
    pub clk: u32,
    pub pc: u32,
    pub instruction: Instruction,
    pub a: u32,
    pub a_record: Option<MemoryRecordEnum>,
    pub b: u32,
    pub b_record: Option<MemoryRecordEnum>,
    pub c: u32,
    pub c_record: Option<MemoryRecordEnum>,
    pub memory: Option<u32>,
    pub memory_record: Option<MemoryRecordEnum>,
}

#[derive(Debug, Copy, Clone)]
pub enum MemoryRecordEnum {
    Read(MemoryReadRecord),
    Write(MemoryWriteRecord),
}

impl MemoryRecordEnum {
    pub fn value(&self) -> u32 {
        match self {
            MemoryRecordEnum::Read(record) => record.value,
            MemoryRecordEnum::Write(record) => record.value,
        }
    }
}

impl From<MemoryReadRecord> for MemoryRecordEnum {
    fn from(read_record: MemoryReadRecord) -> Self {
        MemoryRecordEnum::Read(read_record)
    }
}

impl From<MemoryWriteRecord> for MemoryRecordEnum {
    fn from(write_record: MemoryWriteRecord) -> Self {
        MemoryRecordEnum::Write(write_record)
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct MemoryRecord {
    pub value: u32,
    pub segment: u32,
    pub timestamp: u32,
}

#[derive(Debug, Copy, Clone, Default)]
#[non_exhaustive]
pub struct MemoryReadRecord {
    pub value: u32,
    pub segment: u32,
    pub timestamp: u32,
    pub prev_segment: u32,
    pub prev_timestamp: u32,
}

impl MemoryReadRecord {
    pub fn new(
        value: u32,
        segment: u32,
        timestamp: u32,
        prev_segment: u32,
        prev_timestamp: u32,
    ) -> Self {
        assert!(
            segment > prev_segment || ((segment == prev_segment) && (timestamp > prev_timestamp))
        );
        Self {
            value,
            segment,
            timestamp,
            prev_segment,
            prev_timestamp,
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
#[non_exhaustive]
pub struct MemoryWriteRecord {
    pub value: u32,
    pub segment: u32,
    pub timestamp: u32,
    pub prev_value: u32,
    pub prev_segment: u32,
    pub prev_timestamp: u32,
}

impl MemoryWriteRecord {
    pub fn new(
        value: u32,
        segment: u32,
        timestamp: u32,
        prev_value: u32,
        prev_segment: u32,
        prev_timestamp: u32,
    ) -> Self {
        assert!(
            segment > prev_segment || ((segment == prev_segment) && (timestamp > prev_timestamp)),
        );
        Self {
            value,
            segment,
            timestamp,
            prev_value,
            prev_segment,
            prev_timestamp,
        }
    }
}

pub struct CpuChip;

impl CpuChip {
    pub fn new() -> Self {
        Self {}
    }
}
