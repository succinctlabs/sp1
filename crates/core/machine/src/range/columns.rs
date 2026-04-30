use sp1_derive::AlignedBorrow;
use std::mem::size_of;
use struct_reflection::{StructReflection, StructReflectionHelper};

/// The number of main trace columns for `RangeChip`.
pub const NUM_RANGE_PREPROCESSED_COLS: usize = size_of::<RangePreprocessedCols<u8>>();

/// The number of multiplicity columns for `RangeChip`.
pub const NUM_RANGE_MULT_COLS: usize = size_of::<RangeMultCols<u8>>();

/// The `RangeChip` checks that the input `(a, b)` satisfies `a < 2^b` with `b` value up to `16`.
/// The `RangePreprocessedCols` has all the inputs that satisfy this relation.
#[derive(Debug, Clone, Copy, AlignedBorrow, StructReflection)]
#[repr(C)]
pub struct RangePreprocessedCols<T> {
    /// The value to range check.
    pub a: T,

    /// The number of bits.
    pub bits: T,
}

/// For each range operation in the preprocessed table, a corresponding RangeMultCols row tracks
/// the number of times the operation is used.
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct RangeMultCols<T> {
    /// The multiplicity of each range operation.
    pub multiplicity: T,
}
