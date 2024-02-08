#[derive(Debug, Copy, Clone)]
pub enum MemoryRecordEnum {
    Read(MemoryReadRecord),
    Write(MemoryWriteRecord),
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
