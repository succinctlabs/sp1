use core::borrow::Borrow;
use core::borrow::BorrowMut;
use std::mem::size_of;

use valida_derive::AlignedBorrow;

use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;
use crate::operations::XorOperation;

use super::compress_inner::CompressInnnerOperation;

pub const NUM_BLAKE3_EXTERNAL_COLS: usize = size_of::<Blake3ExternalCols<u8>>();

/// Cols to perform the either the first or the last external round of Blake3.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Blake3ExternalCols<T> {
    pub segment: T,
    pub clk: T,

    pub state_ptr: T,

    pub mem_reads_block_words: [MemoryReadCols<T>; 16],
    pub mem_read_block_len: MemoryReadCols<T>,
    pub mem_read_cv_words: [MemoryReadCols<T>; 8],

    // u64 represented as two u32s.
    pub mem_read_counter: [MemoryReadCols<T>; 2],

    pub mem_read_flag: MemoryReadCols<T>,

    pub mem_writes: [MemoryWriteCols<T>; 8],

    pub compress_inner: CompressInnnerOperation<T>,

    pub final_xor: [XorOperation<T>; 8],

    pub is_real: T,
}
