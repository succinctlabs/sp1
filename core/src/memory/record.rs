#[derive(Debug, Copy, Clone)]
pub enum MemoryRecord {
    /// A read record constisting of a memory read value and previous `(segment, timestamp)`
    /// of the last write time of the memory cell being accessed.
    Read(MemoryReadRecord),
    /// A write record constisting of a memory write value and previous `(segment, timestamp)`
    /// of the last write time of the memory cell being accessed.
    Write(MemoryWriteRecord),
    /// An entry record constisting of a memory entry value and `(segment, timestamp)`.
    ///
    /// This entry is ued in initialization, finalization, and loading the program memory state.
    Entry(MemoryEntryRecord),
}

impl MemoryRecord {
    pub fn new_read(
        value: u32,
        segment: u32,
        timestamp: u32,
        prev_segment: u32,
        prev_timestamp: u32,
    ) -> Self {
        MemoryRecord::Read(MemoryReadRecord::new(
            value,
            segment,
            timestamp,
            prev_segment,
            prev_timestamp,
        ))
    }

    pub fn new_write(
        value: u32,
        segment: u32,
        timestamp: u32,
        prev_value: u32,
        prev_segment: u32,
        prev_timestamp: u32,
    ) -> Self {
        MemoryRecord::Write(MemoryWriteRecord::new(
            value,
            segment,
            timestamp,
            prev_value,
            prev_segment,
            prev_timestamp,
        ))
    }

    pub const fn value(&self) -> u32 {
        match self {
            MemoryRecord::Read(record) => record.value,
            MemoryRecord::Write(record) => record.value,
            MemoryRecord::Entry(record) => record.value,
        }
    }

    #[inline]
    pub fn prev_value(&self) -> u32 {
        match self {
            MemoryRecord::Read(record) => record.value,
            MemoryRecord::Write(record) => record.prev_value,
            _ => unreachable!("MemoryRecord::Entry has no prev_value"),
        }
    }

    pub const fn segment(&self) -> u32 {
        match self {
            MemoryRecord::Read(record) => record.segment,
            MemoryRecord::Write(record) => record.segment,
            MemoryRecord::Entry(record) => record.segment,
        }
    }

    pub fn prev_segment(&self) -> u32 {
        match self {
            MemoryRecord::Read(record) => record.prev_segment,
            MemoryRecord::Write(record) => record.prev_segment,
            _ => unreachable!("MemoryRecord::Entry has no prev_segment"),
        }
    }

    pub fn prev_timestamp(&self) -> u32 {
        match self {
            MemoryRecord::Read(record) => record.prev_timestamp,
            MemoryRecord::Write(record) => record.prev_timestamp,
            _ => unreachable!("MemoryRecord::Entry has no prev_timestamp"),
        }
    }

    pub fn timestamp(&self) -> u32 {
        match self {
            MemoryRecord::Read(record) => record.timestamp,
            MemoryRecord::Write(record) => record.timestamp,
            MemoryRecord::Entry(record) => record.timestamp,
        }
    }
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

#[derive(Debug, Copy, Clone, Default)]
pub struct MemoryEntryRecord {
    pub value: u32,
    pub segment: u32,
    pub timestamp: u32,
}

impl From<MemoryReadRecord> for MemoryRecord {
    fn from(read_record: MemoryReadRecord) -> Self {
        MemoryRecord::Read(read_record)
    }
}

impl From<MemoryWriteRecord> for MemoryRecord {
    fn from(write_record: MemoryWriteRecord) -> Self {
        MemoryRecord::Write(write_record)
    }
}
