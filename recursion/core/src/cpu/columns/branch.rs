use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::air::IsExtZeroOperation;

#[allow(dead_code)]
pub const NUM_BRANCH_COLS: usize = size_of::<BranchCols<u8>>();

/// TODO: we should incorporate these columns into the `OpcodeSpecificCols` union.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BranchCols<T> {
    is_eq_zero: IsExtZeroOperation<T>,
}
