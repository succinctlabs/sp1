use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use super::NUM_RANGE_CHECK_OPS;

/// The number of main trace columns for `RangeCheckChip`.
pub const NUM_RANGE_CHECK_PREPROCESSED_COLS: usize = size_of::<RangeCheckPreprocessedCols<u8>>();

/// The number of multiplicity columns for `RangeCheckChip`.
pub const NUM_RANGE_CHECK_MULT_COLS: usize = size_of::<RangeCheckMultCols<u8>>();

#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct RangeCheckPreprocessedCols<T> {
    /// Value to store all possible U16 values.
    pub value_u16: T,

    /// A flag indicating whether the value is out of U12 range.
    pub u12_out_range: T,
}

/// For each byte operation in the preprocessed table, a corresponding RangeCheckMultCols row tracks the
/// number of times the operation is used.
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct RangeCheckMultCols<T> {
    /// The multiplicites of each byte operation.
    pub multiplicities: [T; NUM_RANGE_CHECK_OPS],
}
