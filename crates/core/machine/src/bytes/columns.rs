use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use super::NUM_BYTE_OPS;

/// The number of main trace columns for `ByteChip`.
pub const NUM_BYTE_PREPROCESSED_COLS: usize = size_of::<BytePreprocessedCols<u8>>();

/// The number of multiplicity columns for `ByteChip`.
pub const NUM_BYTE_MULT_COLS: usize = size_of::<ByteMultCols<u8>>();

#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct BytePreprocessedCols<T> {
    /// The first byte operand.
    pub b: T,

    /// The second byte operand.
    pub c: T,

    /// The result of the `AND` operation on `a` and `b`
    pub and: T,

    /// The result of the `OR` operation on `a` and `b`
    pub or: T,

    /// The result of the `XOR` operation on `a` and `b`
    pub xor: T,

    /// The result of the `SLL` operation on `a` and `b`
    pub sll: T,

    /// The result of the `ShrCarry` operation on `a` and `b`.
    pub shr: T,
    pub shr_carry: T,

    /// The result of the `LTU` operation on `a` and `b`.
    pub ltu: T,

    /// The most significant bit of `b`.
    pub msb: T,

    /// A u16 value used for `U16Range`.
    pub value_u16: T,
}

/// For each byte operation in the preprocessed table, a corresponding ByteMultCols row tracks the
/// number of times the operation is used.
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct ByteMultCols<T> {
    /// The multiplicities of each byte operation.
    pub multiplicities: [T; NUM_BYTE_OPS],
}
