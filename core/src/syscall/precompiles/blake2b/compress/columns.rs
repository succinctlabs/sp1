use core::borrow::{Borrow, BorrowMut};
use std::mem::size_of;

use crate::memory::{MemoryReadCols, MemoryReadWriteCols};
use sp1_derive::AlignedBorrow;

use super::{
    mix::MixOperation, NUM_MIX_ROUNDS, NUM_MSG_WORDS_PER_CALL, NUM_STATE_WORDS_PER_CALL,
    OPERATION_COUNT,
};
use super::{MSG_ELE_PER_CALL, STATE_ELE_PER_CALL};

pub const NUM_BLAKE2B_COMPRESS_INNER_COLS: usize = size_of::<Blake2bCompressInnerCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Blake2bCompressInnerCols<T> {
    pub segment: T,
    pub clk: T,

    /// The pointer to the state.
    pub state_ptr: T,

    /// The pointer to the message.
    pub message_ptr: T,

    /// Reads and writes a part of the state.
    pub state_reads_writes: [MemoryReadWriteCols<T>; NUM_STATE_WORDS_PER_CALL],

    /// Reads a part of the message.
    pub message_reads: [MemoryReadCols<T>; NUM_MSG_WORDS_PER_CALL],

    /// Indicates which call of `mix` is being performed.
    pub operation_index: T,
    pub is_operation_index_n: [T; OPERATION_COUNT],

    /// Indicates which call of `round` is being performed.
    pub mix_round: T,
    pub is_mix_round_index_n: [T; NUM_MIX_ROUNDS],

    /// The indices to pass to `mix`.
    pub state_index: [T; STATE_ELE_PER_CALL],

    /// The two values from `SIGMA_PERMUTATIONS` to pass to `mix`.
    pub message_index: [T; MSG_ELE_PER_CALL],

    /// The `mix` operation to perform.
    pub mix: MixOperation<T>,

    /// Indicates if the current call is real or not.
    pub is_real: T,
}
