use crate::precompiles::blake3::INPUT_SIZE;
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use std::mem::size_of;

use valida_derive::AlignedBorrow;

use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;

use super::compress_inner::CompressInnerOperation;
use super::MIX_OPERATION_OUTPUT_SIZE;

pub const NUM_BLAKE3_COMPRESS_INNER_COLS: usize = size_of::<Blake3CompressInnerCols<u8>>();

/// Cols to perform the Compress
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Blake3CompressInnerCols<T> {
    pub segment: T,
    pub clk: T,

    pub state_ptr: T,

    /// Reads in parts of the state.
    pub mem_reads_input: [MemoryReadCols<T>; INPUT_SIZE],

    /// Writes the updated state.
    pub mem_writes: [MemoryWriteCols<T>; MIX_OPERATION_OUTPUT_SIZE],

    pub compress_inner: CompressInnerOperation<T>,

    pub is_real: T,
}
