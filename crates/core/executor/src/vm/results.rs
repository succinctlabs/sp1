use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::{
    events::{MemoryReadRecord, MemoryWriteRecord},
    Instruction, Register, TrapError,
};

/// For untrusted programs, fetching an instruction might lead to a memory read
/// and a decoding phase. It's likely we will need new records here.
pub struct FetchResult {
    pub pc: u64,
    pub instruction: Option<Instruction>,
    pub mr_record: Option<MemoryReadRecord>,
    pub error: Option<TrapError>,
}

pub struct LoadResultSupervisor {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub addr: u64,
    pub rs1: Register,
    pub mr_record: MemoryReadRecord,
    pub rd: Register,
    pub rr_record: MemoryReadRecord,
    pub rw_record: MemoryWriteRecord,
}

pub struct LoadResult {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub addr: u64,
    pub rs1: Register,
    pub mr_record: MemoryReadRecord,
    pub rd: Register,
    pub rr_record: MemoryReadRecord,
    pub rw_record: MemoryWriteRecord,
    pub error: Option<TrapError>,
}

pub struct StoreResultSupervisor {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub addr: u64,
    pub rs1: Register,
    pub rs1_record: MemoryReadRecord,
    pub rs2: Register,
    pub rs2_record: MemoryReadRecord,
    pub mw_record: MemoryWriteRecord,
}

pub struct StoreResult {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub addr: u64,
    pub rs1: Register,
    pub rs1_record: MemoryReadRecord,
    pub rs2: Register,
    pub rs2_record: MemoryReadRecord,
    pub mw_record: MemoryWriteRecord,
    pub error: Option<TrapError>,
}

pub struct AluResult {
    pub rd: Register,
    pub rw_record: MemoryWriteRecord,
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub rs1: MaybeImmediate,
    pub rs2: MaybeImmediate,
}

pub enum MaybeImmediate {
    Register(Register, MemoryReadRecord),
    Immediate(u64),
}

impl MaybeImmediate {
    pub fn record(&self) -> Option<&MemoryReadRecord> {
        match self {
            MaybeImmediate::Register(_, record) => Some(record),
            MaybeImmediate::Immediate(_) => None,
        }
    }
}

pub struct JumpResult {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub rd: Register,
    pub rd_record: MemoryWriteRecord,
    pub rs1: MaybeImmediate,
}

pub struct BranchResult {
    pub a: u64,
    pub rs1: Register,
    pub a_record: MemoryReadRecord,
    pub b: u64,
    pub rs2: Register,
    pub b_record: MemoryReadRecord,
    pub c: u64,
}

pub struct UTypeResult {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub rd: Register,
    pub rw_record: MemoryWriteRecord,
}

pub struct EcallResult {
    pub a: u64,
    pub a_record: MemoryWriteRecord,
    pub b: u64,
    pub b_record: MemoryReadRecord,
    pub c: u64,
    pub c_record: MemoryReadRecord,
    pub error: Option<TrapError>,
    pub sig_return_pc_record: Option<MemoryReadRecord>,
}

/// The result of a cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleResult {
    /// The cycle has completed, and may or may not have halted.
    Done(bool),
    /// The trace has ended at this cycle.
    TraceEnd,
    /// The shard has overflowed at this cycle.
    ShardBoundary,
}

impl CycleResult {
    /// Returns true if the program has halted.
    #[must_use]
    pub fn is_done(self) -> bool {
        matches!(self, CycleResult::Done(true))
    }

    /// Returns true if the program has hit a shard boundary.
    #[must_use]
    pub fn is_shard_boundry(self) -> bool {
        matches!(self, CycleResult::ShardBoundary)
    }

    /// Returns true if the trace has ended at this cycle.
    #[must_use]
    pub fn is_trace_end(self) -> bool {
        matches!(self, CycleResult::TraceEnd)
    }
}

/// The result of the trap handling.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, DeepSizeOf)]
#[repr(C)]
pub struct TrapResult {
    /// The trap context.
    pub context: u64,
    /// The memory record for writing the trap code.
    pub code_record: MemoryWriteRecord,
    /// The memory record for writing the program counter.
    pub pc_record: MemoryWriteRecord,
    /// The memory record for reading the next program counter.
    pub handler_record: MemoryReadRecord,
}
