use std::mem::size_of;

use sp1_derive::AlignedBorrow;

use crate::memory::MemoryReadCols;
use crate::memory::MemoryReadWriteCols;

use super::g::GOperation;
use super::NUM_MSG_WORDS_PER_CALL;
use super::NUM_STATE_WORDS_PER_CALL;
use super::OPERATION_COUNT;
use super::ROUND_COUNT;

pub const NUM_BLAKE3_COMPRESS_INNER_COLS: usize = size_of::<Blake3CompressInnerCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Blake3CompressInnerCols<T> {
    pub shard: T,
    pub channel: T,
    pub clk: T,
    pub ecall_receive: T,

    /// The pointer to the state.
    pub state_ptr: T,

    /// The pointer to the message.
    pub message_ptr: T,

    /// Reads and writes a part of the state.
    pub state_reads_writes: [MemoryReadWriteCols<T>; NUM_STATE_WORDS_PER_CALL],

    /// Reads a part of the message.
    pub message_reads: [MemoryReadCols<T>; NUM_MSG_WORDS_PER_CALL],

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

    /// The `g` operation to perform.
    pub g: GOperation<T>,

    /// Indicates if the current call is real or not.
    pub is_real: T,
}
