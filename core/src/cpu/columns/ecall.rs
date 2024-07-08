use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::{
    air::{Word, PV_DIGEST_NUM_WORDS},
    operations::{BabyBearWordRangeChecker, IsZeroOperation},
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

    /// Whether the current ecall is a COMMIT_DEFERRED_PROOFS.
    pub is_commit_deferred_proofs: IsZeroOperation<T>,

    /// Field to store the word index passed into the COMMIT ecall.  index_bitmap[word index] should
    /// be set to 1 and everything else set to 0.
    pub index_bitmap: [T; PV_DIGEST_NUM_WORDS],

    /// The nonce of the syscall operation.
    pub syscall_nonce: T,

    /// Columns to babybear range check the halt/commit_deferred_proofs operand.
    pub operand_range_check_cols: BabyBearWordRangeChecker<T>,

    /// The operand value to babybear range check.
    pub operand_to_check: Word<T>,
}
