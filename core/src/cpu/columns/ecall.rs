use sp1_derive::AlignedBorrow;
use sp1_zkvm::PI_DIGEST_NUM_WORDS;
use std::mem::size_of;

use crate::{air::Word, operations::IsZeroOperation};

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
    pub digest_word: Word<T>,
    pub index_bitmap: [T; PI_DIGEST_NUM_WORDS],
}
