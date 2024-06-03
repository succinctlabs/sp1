use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::{air::Word, operations::BabyBearWordRangeChecker};

pub const NUM_BRANCH_COLS: usize = size_of::<BranchCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BranchCols<T> {
    /// The current program counter.
    pub pc: Word<T>,
    pub pc_range_checker: BabyBearWordRangeChecker<T>,

    /// The next program counter.
    pub next_pc: Word<T>,
    pub next_pc_range_checker: BabyBearWordRangeChecker<T>,

    /// Whether a equals b.
    pub a_eq_b: T,

    /// Whether a is greater than b.
    pub a_gt_b: T,

    /// Whether a is less than b.
    pub a_lt_b: T,

    /// The nonce of the operation to compute `a_lt_b`.
    pub a_lt_b_nonce: T,

    /// The nonce of the operation to compute `a_gt_b`.
    pub a_gt_b_nonce: T,

    /// The nonce of the operation to compute `next_pc`.
    pub next_pc_nonce: T,
}
