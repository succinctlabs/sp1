use serde::{Deserialize, Serialize};

/// An record of a write to a memory address.
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub struct MemoryRecord {
    /// The value at the memory address.
    pub value: u32,

    /// The shard in which the memory address was last written to.
    pub shard: u32,

    /// The timestamp at which the memory address was last written to.
    pub timestamp: u32,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MemoryAccessPosition {
    Memory = 0,
    // Note that these AccessPositions mean that when when read/writing registers, they must be
    // read/written in the following order: C, B, A.
    C = 1,
    B = 2,
    A = 3,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum MemoryRecordEnum {
    Read(MemoryReadRecord),
    Write(MemoryWriteRecord),
}

#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub struct MemoryReadRecord {
    pub value: u32,
    pub shard: u32,
    pub timestamp: u32,
    pub prev_shard: u32,
    pub prev_timestamp: u32,
    _private: (),
}

#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub struct MemoryWriteRecord {
    pub value: u32,
    pub shard: u32,
    pub timestamp: u32,
    pub prev_value: u32,
    pub prev_shard: u32,
    pub prev_timestamp: u32,
    _private: (),
}

impl MemoryRecordEnum {
    pub const fn value(&self) -> u32 {
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
    pub const fn new(
        value: u32,
        shard: u32,
        timestamp: u32,
        prev_shard: u32,
        prev_timestamp: u32,
    ) -> Self {
        assert!(shard > prev_shard || ((shard == prev_shard) && (timestamp > prev_timestamp)));
        Self {
            value,
            shard,
            timestamp,
            prev_shard,
            prev_timestamp,
            _private: (),
        }
    }
}

impl MemoryWriteRecord {
    pub const fn new(
        value: u32,
        shard: u32,
        timestamp: u32,
        prev_value: u32,
        prev_shard: u32,
        prev_timestamp: u32,
    ) -> Self {
        assert!(shard > prev_shard || ((shard == prev_shard) && (timestamp > prev_timestamp)),);
        Self {
            value,
            shard,
            timestamp,
            prev_value,
            prev_shard,
            prev_timestamp,
            _private: (),
        }
    }
}
