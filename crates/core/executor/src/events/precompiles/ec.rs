use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};

use crate::events::{
    memory::{MemoryReadRecord, MemoryWriteRecord},
    MemoryLocalEvent, PageProtLocalEvent, PageProtRecord,
};

/// Elliptic Curve Page Prot Records.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf, PartialEq, Eq)]
pub struct EllipticCurvePageProtRecords {
    /// The page prot records for reading the address.
    pub read_page_prot_records: Vec<PageProtRecord>,
    /// The page prot records for writing the address.
    pub write_page_prot_records: Vec<PageProtRecord>,
}

/// Elliptic Curve Add Event.
///
/// This event is emitted when an elliptic curve addition operation is performed.
#[derive(Default, Debug, Clone, Serialize, PartialEq, Eq, Deserialize, DeepSizeOf)]
pub struct EllipticCurveAddEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The pointer to the first point.
    pub p_ptr: u64,
    /// The first point as a list of words.
    pub p: Vec<u64>,
    /// The pointer to the second point.
    pub q_ptr: u64,
    /// The second point as a list of words.
    pub q: Vec<u64>,
    /// The memory records for the first point.
    pub p_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for the second point.
    pub q_memory_records: Vec<MemoryReadRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// The page prot records.
    pub page_prot_records: EllipticCurvePageProtRecords,
    /// The local page prot access records.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}

/// Elliptic Curve Double Event.
///
/// This event is emitted when an elliptic curve doubling operation is performed.
#[derive(Default, Debug, Clone, Serialize, PartialEq, Eq, Deserialize, DeepSizeOf)]
pub struct EllipticCurveDoubleEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The pointer to the point.
    pub p_ptr: u64,
    /// The point as a list of words.
    pub p: Vec<u64>,
    /// The memory records for the point.
    pub p_memory_records: Vec<MemoryWriteRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// Write slice page prot access records.
    pub write_slice_page_prot_access: Vec<PageProtRecord>,
    /// The local page prot access records.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}

/// Elliptic Curve Point Decompress Event.
///
/// This event is emitted when an elliptic curve point decompression operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize, DeepSizeOf)]
pub struct EllipticCurveDecompressEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The pointer to the point.
    pub ptr: u64,
    /// The sign bit of the point.
    pub sign_bit: bool,
    /// The x coordinate as a list of bytes.
    pub x_bytes: Vec<u8>,
    /// The decompressed y coordinate as a list of bytes.
    pub decompressed_y_bytes: Vec<u8>,
    /// The memory records for the x coordinate.
    pub x_memory_records: Vec<MemoryReadRecord>,
    /// The memory records for the y coordinate.
    pub y_memory_records: Vec<MemoryWriteRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// The page prot records.
    pub page_prot_records: EllipticCurvePageProtRecords,
    /// The local page prot access records.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
}

/// Elliptic Curve Scalar Multiplication Event.
///
/// This event is emitted when an elliptic curve point is multiplied by a `BigUint` scalar.
#[derive(Default, Debug, Clone, Serialize, PartialEq, Eq, Deserialize, DeepSizeOf)]
pub struct EllipticCurveMulEvent {
    /// The clock cycle.
    pub clk: u64,
    /// The pointer to the point.
    pub p_ptr: u64,
    /// The point as a list of words.
    pub p: Vec<u64>,
    /// The pointer to the scalar.
    pub exp_ptr: u64,
    /// The scalar as a list of little-endian `u64` limbs.
    pub exp: Vec<u64>,
    /// The memory records for the point (read-then-write in place).
    pub p_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for the scalar (read-only).
    pub exp_memory_records: Vec<MemoryReadRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// The page prot records (read slice for the scalar, write slice for the point).
    pub page_prot_records: EllipticCurvePageProtRecords,
    /// The local page prot access records.
    pub local_page_prot_access: Vec<PageProtLocalEvent>,
    /// Whether this syscall trapped on an mprotect check.
    ///
    /// When `true`, the executor leaves `p`, `exp`, and the memory-record vectors
    /// empty and emits no work for the internal Add / Double chips, so they can
    /// short-circuit their per-event row counts to 0 without re-deriving trap
    /// status from `page_prot_records`.
    pub is_trapped: bool,
}

/// Internal event emitted for each addition step in elliptic curve scalar multiplication.
///
/// `clk` rides on the event so the internal chips can drain the channel in any
/// order — the controller can then populate its rows in parallel without
/// preserving per-event ordering on the channel.
#[derive(Default, Debug, Clone, Serialize, PartialEq, Eq, Deserialize, DeepSizeOf)]
pub struct ECMulInternalAddEvent {
    /// parent ECMUL event's clock cycle
    pub clk: u64,
    /// internal step counter
    pub c: u16,
    /// first add marker (the prefix bit-sum `S_{i-1}`, always non-zero for events
    /// that reach this chip; the first add is absorbed by the controller)
    pub is_first_add: u16,
    /// input running doubler
    pub ird: Vec<u64>,
    /// input running total
    pub irt: Vec<u64>,
}

/// Internal event emitted for each doubling step in elliptic curve scalar multiplication.
///
/// See [`ECMulInternalAddEvent`] for the rationale behind carrying `clk`.
#[derive(Default, Debug, Clone, Serialize, PartialEq, Eq, Deserialize, DeepSizeOf)]
pub struct ECMulInternalDoubleEvent {
    /// parent ECMUL event's clock cycle
    pub clk: u64,
    /// internal step counter
    pub c: u16,
    /// input running doubler
    pub ird: Vec<u64>,
    /// input running total
    pub irt: Vec<u64>,
}
