use sp1_derive::AlignedBorrow;
use sp1_stark::Word;
use std::mem::size_of;

pub const NUM_AUIPC_COLS: usize = size_of::<AuipcCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AuipcCols<T> {
    /// The current program counter. Important that this field be the first one in the struct, for
    /// the `get_most_significant_byte` function on `OpcodeSelectorCols` to be correct.
    pub pc: Word<T>,
    /// Important that this be the first field after the Word<T> field, in order for the
    /// `get_range_check_bit` function on `OpcodeSelectorCols` to be correct.
    pub pc_range_checker: T,
    pub auipc_nonce: T,
}
