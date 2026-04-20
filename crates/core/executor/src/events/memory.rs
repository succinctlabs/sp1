use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

/// The number of local memory entries per row of the memory local chip.
pub const NUM_LOCAL_MEMORY_ENTRIES_PER_ROW_EXEC: usize = 1;

/// The number of page prot entries per row of the page prot local chip.
pub const NUM_LOCAL_PAGE_PROT_ENTRIES_PER_ROW_EXEC: usize = 1;

/// The number of page prot entries per row of the page prot local chip.
pub const NUM_PAGE_PROT_ENTRIES_PER_ROW_EXEC: usize = 4;

/// Memory Record.
///
/// This object encapsulates the information needed to prove a memory access operation. This
/// includes the timestamp and the value of the memory address.
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize, PartialEq, Eq, DeepSizeOf)]
#[repr(C)]
pub struct MemoryRecord {
    /// The timestamp.
    pub timestamp: u64,
    /// The value.
    pub value: u64,
}

/// Memory entry.
///
/// Similar to a [`MemoryRecord`], but it contains/validates data for execution purposes.
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub struct MemoryEntry {
    /// The external flag.
    pub external_flag: bool,
    /// The timestamp.
    pub timestamp: u64,
    /// The value.
    pub value: u64,
}

impl MemoryEntry {
    /// Create a memory entry that represents the program-wide initialization of a value.
    #[must_use]
    pub fn init(value: u64) -> Self {
        Self { external_flag: false, timestamp: 0, value }
    }
}

impl From<MemoryEntry> for MemoryRecord {
    /// Converts to a `MemoryRecord` from a `MemoryEntry`.
    fn from(value: MemoryEntry) -> Self {
        let MemoryEntry { timestamp, value, .. } = value;
        Self { timestamp, value }
    }
}

/// Memory Access Position.
///
/// This enum represents the position of a memory access in a register. For example, if a memory
/// access is performed in the C register, it will have a position of C.
///
/// Note: The register positions require that they be read and written in the following order:
/// C, B, A.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MemoryAccessPosition {
    /// Untrusted instruction access position.
    UntrustedInstruction = 0,
    /// Memory access position.
    Memory = 1,
    /// C register access position.
    C = 2,
    /// B register access position.
    B = 3,
    /// A register access position.
    A = 4,
}

/// Memory Read Record.
///
/// This object encapsulates the information needed to prove a memory read operation. This
/// includes the value, timestamp, and the previous timestamp.
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize, PartialEq, Eq, DeepSizeOf)]
#[repr(C)]
pub struct MemoryReadRecord {
    /// The value.
    pub value: u64,
    /// The timestamp.
    pub timestamp: u64,
    /// The previous timestamp.
    pub prev_timestamp: u64,
    /// The page prot record.
    pub prev_page_prot_record: Option<PageProtRecord>,
}

/// Memory Write Record.
///
/// This object encapsulates the information needed to prove a memory write operation. This
/// includes the value, timestamp, previous value, and previous timestamp.
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize, PartialEq, Eq, DeepSizeOf)]
#[repr(C)]
pub struct MemoryWriteRecord {
    /// The previous timestamp.
    pub prev_timestamp: u64,
    /// The page prot record.
    pub prev_page_prot_record: Option<PageProtRecord>,
    /// The previous value.
    pub prev_value: u64,
    /// The timestamp.
    pub timestamp: u64,
    /// The value.
    pub value: u64,
}

/// Memory Record Enum.
///
/// This enum represents the different types of memory records that can be stored in the memory
/// event such as reads and writes.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, DeepSizeOf)]
pub enum MemoryRecordEnum {
    /// Read.
    Read(MemoryReadRecord),
    /// Write.
    Write(MemoryWriteRecord),
}

impl MemoryRecordEnum {
    /// Retrieve the current memory record.
    #[must_use]
    pub fn current_record(&self) -> MemoryRecord {
        match self {
            MemoryRecordEnum::Read(record) => {
                MemoryRecord { timestamp: record.timestamp, value: record.value }
            }
            MemoryRecordEnum::Write(record) => {
                MemoryRecord { timestamp: record.timestamp, value: record.value }
            }
        }
    }

    /// Retrieve the previous memory record.
    #[must_use]
    pub fn previous_record(&self) -> MemoryRecord {
        match self {
            MemoryRecordEnum::Read(record) => {
                MemoryRecord { timestamp: record.prev_timestamp, value: record.value }
            }
            MemoryRecordEnum::Write(record) => {
                MemoryRecord { timestamp: record.prev_timestamp, value: record.prev_value }
            }
        }
    }

    /// Retrieve the previous page prot record.
    #[must_use]
    pub fn previous_page_prot_record(&self) -> Option<PageProtRecord> {
        match self {
            MemoryRecordEnum::Read(record) => record.prev_page_prot_record,
            MemoryRecordEnum::Write(record) => record.prev_page_prot_record,
        }
    }
}

/// Memory Initialize/Finalize Event.
///
/// This object encapsulates the information needed to prove a memory initialize or finalize
/// operation. This includes the address, value, and the timestamp.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, DeepSizeOf)]
#[repr(C)]
pub struct MemoryInitializeFinalizeEvent {
    /// The address.
    pub addr: u64,
    /// The value.
    pub value: u64,
    /// The timestamp.
    pub timestamp: u64,
}

/// Page prot Initialize/Finalize Event.
///
/// This object encapsulates the information needed to prove a page prot initialize or finalize
/// operation. This includes the page index, page prot, and timestamp.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, DeepSizeOf)]
#[repr(C)]
pub struct PageProtInitializeFinalizeEvent {
    /// The page index.
    pub page_idx: u64,
    /// The page prot.
    pub page_prot: u8,
    /// The timestamp.
    pub timestamp: u64,
}

impl PageProtInitializeFinalizeEvent {
    /// Creates a new [``PageProtInitializeFinalizeEvent``] for an initialization.
    #[must_use]
    pub const fn initialize(page_idx: u64, page_prot: u8) -> Self {
        Self { page_idx, page_prot, timestamp: 0 }
    }

    /// Creates a new [``PageProtInitializeFinalizeEvent``] for a finalization.
    #[must_use]
    pub const fn finalize_from_record(page_idx: u64, record: &PageProtRecord) -> Self {
        Self { page_idx, page_prot: record.page_prot, timestamp: record.timestamp }
    }
}

impl MemoryReadRecord {
    /// Creates a new [``MemoryReadRecord``].
    #[must_use]
    #[inline]
    pub const fn new(
        entry: &MemoryEntry,
        prev_entry: &MemoryEntry,
        prev_page_prot_record: Option<PageProtRecord>,
    ) -> Self {
        let MemoryEntry { timestamp, value, .. } = *entry;
        let MemoryEntry { timestamp: prev_timestamp, value: _, .. } = *prev_entry;
        debug_assert!(timestamp > prev_timestamp);
        Self { value, timestamp, prev_timestamp, prev_page_prot_record }
    }
}

impl From<MemoryRecordEnum> for MemoryReadRecord {
    fn from(record: MemoryRecordEnum) -> Self {
        match record {
            MemoryRecordEnum::Read(record) => record,
            MemoryRecordEnum::Write(_) => panic!("Cannot convert a write record to a read record"),
        }
    }
}

impl MemoryWriteRecord {
    /// Creates a new [``MemoryWriteRecord``].
    #[must_use]
    #[inline]
    pub const fn new(
        entry: &MemoryEntry,
        prev_entry: &MemoryEntry,
        prev_page_prot_record: Option<PageProtRecord>,
    ) -> Self {
        let MemoryEntry { timestamp, value, .. } = *entry;
        let MemoryEntry { timestamp: prev_timestamp, value: prev_value, .. } = *prev_entry;
        debug_assert!(timestamp > prev_timestamp);
        Self { prev_timestamp, prev_page_prot_record, prev_value, timestamp, value }
    }
}

impl MemoryRecordEnum {
    /// Returns the value of the memory record.
    #[must_use]
    pub const fn value(&self) -> u64 {
        match self {
            MemoryRecordEnum::Read(record) => record.value,
            MemoryRecordEnum::Write(record) => record.value,
        }
    }

    /// Returns the previous value of the memory record.
    #[must_use]
    pub const fn prev_value(&self) -> u64 {
        match self {
            MemoryRecordEnum::Read(record) => record.value,
            MemoryRecordEnum::Write(record) => record.prev_value,
        }
    }
}

impl MemoryInitializeFinalizeEvent {
    /// Creates a new [``MemoryInitializeFinalizeEvent``] for an initialization.
    #[must_use]
    pub const fn initialize(addr: u64, value: u64) -> Self {
        Self { addr, value, timestamp: 0 }
    }

    /// Creates a new [``MemoryInitializeFinalizeEvent``] for a finalization.
    #[must_use]
    pub const fn finalize_from_record(addr: u64, record: &MemoryEntry) -> Self {
        Self { addr, value: record.value, timestamp: record.timestamp }
    }

    /// Creates a new [``MemoryInitializeFinalizeEvent``].
    #[must_use]
    pub const fn finalize(addr: u64, value: u64, timestamp: u64) -> Self {
        Self { addr, value, timestamp }
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

/// Memory Local Event.
///
/// This object encapsulates the information needed to prove a memory access operation within a
/// shard. This includes the address, initial memory access, and final memory access within a
/// shard.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, DeepSizeOf)]
#[repr(C)]
pub struct MemoryLocalEvent {
    /// The address.
    pub addr: u64,
    /// The initial memory access.
    pub initial_mem_access: MemoryRecord,
    /// The final memory access.
    pub final_mem_access: MemoryRecord,
}

/// Page Prot Record.
///
/// This object encapsulates the information needed to prove a page prot access operation. This
/// includes the clk and page prot value.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, DeepSizeOf, PartialEq, Eq)]
#[repr(C)]
pub struct PageProtRecord {
    /// The external flag.
    // TODO: in native executor design, shape checker actually relies on outside data
    // to determine if the page prot event is external. So maybe when the legacy executor
    // is removed, we don't really need this flag.
    pub external_flag: bool,
    /// The timestamp.
    pub timestamp: u64,
    /// The page index.
    pub page_idx: u64,
    /// The page prot.
    pub page_prot: u8,
}

/// Page Prot Local Event.
///
/// This object encapsulates the information needed to prove a page prot access operation within a
/// shard. This includes the page, initial page access, and final page access within a
/// shard.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, DeepSizeOf)]
#[repr(C)]
pub struct PageProtLocalEvent {
    /// The page idx.
    pub page_idx: u64,
    /// The initial page prot access.
    pub initial_page_prot_access: PageProtRecord,
    /// The final page prot access.
    pub final_page_prot_access: PageProtRecord,
}

/// Trait to convert something into a [`MemoryRecord`].
pub trait IntoMemoryRecord {
    /// Get the previous record.
    fn previous_record(&self) -> MemoryRecord;

    /// Get the current record.
    fn current_record(&self) -> MemoryRecord;
}

impl IntoMemoryRecord for MemoryReadRecord {
    fn previous_record(&self) -> MemoryRecord {
        MemoryRecord { timestamp: self.prev_timestamp, value: self.value }
    }

    fn current_record(&self) -> MemoryRecord {
        MemoryRecord { timestamp: self.timestamp, value: self.value }
    }
}

impl IntoMemoryRecord for MemoryWriteRecord {
    fn previous_record(&self) -> MemoryRecord {
        MemoryRecord { timestamp: self.prev_timestamp, value: self.prev_value }
    }

    fn current_record(&self) -> MemoryRecord {
        MemoryRecord { timestamp: self.timestamp, value: self.value }
    }
}
