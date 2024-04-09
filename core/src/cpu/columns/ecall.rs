use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::{
    air::{Word, PV_DIGEST_NUM_WORDS},
    operations::IsZeroOperation,
};

pub const NUM_ECALL_COLS: usize = size_of::<EcallCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct EcallCols<T> {
    /// Whether the current ecall is ENTER_UNCONSTRAINED.
    pub is_enter_unconstrained: IsZeroOperation<T>,

    /// Whether the current ecall is HINT_LEN.
    pub is_hint_len: IsZeroOperation<T>,

    /// Whether the current ecall is HALT.
    pub is_halt: IsZeroOperation<T>,

    /// Whether the current ecall is a COMMIT.
    pub is_commit: IsZeroOperation<T>,
    /// The digest word passed into the COMMIT ecall. This is the public values digest word calculated
    /// within the program.
    pub digest_word: Word<T>,
    /// Field to store the word index passed into the COMMIT ecall.  index_bitmap[word index] should
    /// be set to 1 and everything else set to 0.
    pub index_bitmap: [T; PV_DIGEST_NUM_WORDS],
}
