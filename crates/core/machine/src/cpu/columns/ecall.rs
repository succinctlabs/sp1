use sp1_derive::AlignedBorrow;
use sp1_stark::{air::PV_DIGEST_NUM_WORDS, Word};
use std::mem::size_of;

use crate::operations::IsZeroOperation;

pub const NUM_ECALL_COLS: usize = size_of::<EcallCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct EcallCols<T> {
    /// The operand value to babybear range check. Important that this field be the first one in the
    /// struct, for the `get_most_significant_byte` function on `OpcodeSelectorCols` to be correct.
    pub operand_to_check: Word<T>,

    /// Important that this be the first field after the Word<T> field, in order for the
    /// `get_range_check_bit` function on `OpcodeSelectorCols` to be correct.
    pub operand_range_check_col: T,

    /// Whether the current ecall is ENTER_UNCONSTRAINED.
    pub is_enter_unconstrained: IsZeroOperation<T>,

    /// Whether the current ecall is HINT_LEN.
    pub is_hint_len: IsZeroOperation<T>,

    /// Whether the current ecall is HALT.
    pub is_halt: IsZeroOperation<T>,

    /// Whether the current ecall is a COMMIT.
    pub is_commit: IsZeroOperation<T>,

    /// Whether the current ecall is a COMMIT_DEFERRED_PROOFS.
    pub is_commit_deferred_proofs: IsZeroOperation<T>,

    /// Field to store the word index passed into the COMMIT ecall.  index_bitmap[word index]
    /// should be set to 1 and everything else set to 0.
    pub index_bitmap: [T; PV_DIGEST_NUM_WORDS],

    /// The nonce of the syscall operation.
    pub syscall_nonce: T,
}
