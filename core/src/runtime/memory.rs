use serde::{Deserialize, Serialize};

const MAX_MEMORY_SIZE: usize = 1 << 29;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutionMemory {
    pub memory: Vec<MemoryRecord>,
    pub registers: [MemoryRecord; 32],
}

impl ExecutionMemory {
    pub fn new() -> Self {
        let mut memory = Vec::with_capacity(MAX_MEMORY_SIZE / 4);
        memory.resize(MAX_MEMORY_SIZE / 4, MemoryRecord::default());
        Self {
            memory,
            registers: [MemoryRecord::default(); 32],
        }
    }

    #[inline]
    pub fn get(&self, addr: u32) -> &MemoryRecord {
        if addr < 32 {
            &self.registers[addr as usize]
        } else {
            &self.memory[(addr / 4) as usize]
        }
    }

    #[inline]
    pub fn get_mut(&mut self, addr: u32) -> &mut MemoryRecord {
        if addr < 32 {
            &mut self.registers[addr as usize]
        } else {
            &mut self.memory[(addr / 4) as usize]
        }
    }

    #[inline]
    pub fn set(&mut self, addr: u32, record: MemoryRecord) {
        if addr < 32 {
            self.registers[addr as usize] = record;
        } else {
            self.memory[(addr / 4) as usize] = record;
        }
    }
}

#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
#[repr(C)]
pub struct MemoryRecord {
    pub value: u32,
    pub shard: u32,
    pub timestamp: u32,
}

impl MemoryRecord {
    pub fn is_initialized(&self) -> bool {
        self.timestamp == 0
    }
}

#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MemoryReadRecord {
    pub value: u32,
    pub shard: u32,
    pub timestamp: u32,
    pub prev_shard: u32,
    pub prev_timestamp: u32,
}

#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MemoryWriteRecord {
    pub value: u32,
    pub shard: u32,
    pub timestamp: u32,
    pub prev_value: u32,
    pub prev_shard: u32,
    pub prev_timestamp: u32,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
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

impl MemoryReadRecord {
    pub fn new(
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
        }
    }
}

impl MemoryWriteRecord {
    pub fn new(
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
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AccessPosition {
    Memory = 0,
    // Note that these AccessPositions mean that when when read/writing registers, they must be
    // read/written in the following order: C, B, A.
    C = 1,
    B = 2,
    A = 3,
}
