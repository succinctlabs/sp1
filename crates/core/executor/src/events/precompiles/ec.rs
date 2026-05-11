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
    pub scalar_ptr: u64,
    /// The scalar as a list of little-endian `u64` limbs.
    pub scalar: Vec<u64>,
    /// The memory records for the point (read-then-write in place).
    pub p_memory_records: Vec<MemoryWriteRecord>,
    /// The memory records for the scalar (read-only).
    pub scalar_memory_records: Vec<MemoryReadRecord>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
    /// Read slice page prot access records (for the scalar).
    pub read_slice_page_prot_access: Vec<PageProtRecord>,
    /// Write slice page prot access records (for the point).
    pub write_slice_page_prot_access: Vec<PageProtRecord>,
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
