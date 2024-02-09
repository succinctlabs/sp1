use core::borrow::Borrow;
use core::borrow::BorrowMut;
use std::mem::size_of;

use valida_derive::AlignedBorrow;

use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;

use super::compress_inner::CompressInnerOperation;
use super::G_INPUT_SIZE;
use super::G_OUTPUT_SIZE;
use super::NUM_MSG_WORDS_PER_CALL;
use super::NUM_STATE_WORDS_PER_CALL;
use super::OPERATION_COUNT;
use super::ROUND_COUNT;

pub const NUM_BLAKE3_COMPRESS_INNER_COLS: usize = size_of::<Blake3CompressInnerCols<u8>>();

/// Cols to perform the Compress
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Blake3CompressInnerCols<T> {
    pub segment: T,
    pub clk: T,

    pub state_ptr: T,

    /// Reads in parts of the state.
    pub mem_reads: [MemoryReadCols<T>; G_INPUT_SIZE],

    /// Writes the updated state.
    pub mem_writes: [MemoryWriteCols<T>; G_OUTPUT_SIZE],

    /// Indicates which call of `g` is being performed.
    pub operation_index: T,

    pub is_operation_index_n: [T; OPERATION_COUNT],

    /// Indicates which call of `round` is being performed.
    pub round_index: T,

    pub is_round_index_n: [T; ROUND_COUNT],

    /// The indices to pass to `g`.
    pub state_index: [T; NUM_STATE_WORDS_PER_CALL],

    /// The two values from `MSG_SCHEDULE` to pass to `g`.
    pub msg_schedule: [T; NUM_MSG_WORDS_PER_CALL],

    pub compress_inner: CompressInnerOperation<T>,

    pub is_real: T,
}
