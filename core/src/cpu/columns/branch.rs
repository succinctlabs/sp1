use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::{air::Word, operations::BabyBearRangeChecker};

pub const NUM_BRANCH_COLS: usize = size_of::<BranchCols<u8>>();

/// The column layout for branching.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BranchCols<T> {
    /// The current program counter.
    pub pc: Word<T>,
    pub pc_range_checker: BabyBearRangeChecker<T>,

    /// The next program counter.
    pub next_pc: Word<T>,
    pub next_pc_range_checker: BabyBearRangeChecker<T>,

    /// The range checker for `op_a` which may contain `pc + 4`.
    pub op_a_range_checker: BabyBearRangeChecker<T>,

    /// Whether a equals b.
    pub a_eq_b: T,

    /// Whether a is greater than b.
    pub a_gt_b: T,

    /// Whether a is less than b.
    pub a_lt_b: T,
}
