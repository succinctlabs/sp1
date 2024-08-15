use sp1_derive::AlignedBorrow;
use sp1_stark::air::BinomialExtension;
use std::mem::size_of;

use crate::air::IsExtZeroOperation;

#[allow(dead_code)]
pub const NUM_BRANCH_COLS: usize = size_of::<BranchCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BranchCols<T> {
    pub(crate) comparison_diff: IsExtZeroOperation<T>,
    pub(crate) comparison_diff_val: BinomialExtension<T>,
    pub(crate) do_branch: T,
    pub(crate) next_pc: T,
}
