use p3_air::BaseAir;
use sp1_derive::AlignedBorrow;
use sp1_stark::Word;
use std::mem::size_of;

use crate::operations::BabyBearWordRangeChecker;

#[derive(Default)]
pub struct AUIPCChip;

pub const NUM_AUIPC_COLS: usize = size_of::<AUIPCColumns<u8>>();

impl<F> BaseAir<F> for AUIPCChip {
    fn width(&self) -> usize {
        NUM_AUIPC_COLS
    }
}

/// The column layout for memory.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AUIPCColumns<T> {
    /// The program counter of the instruction.
    pub pc: Word<T>,

    /// The value of the first operand.
    pub op_a_value: Word<T>,
    /// The value of the second operand.
    pub op_b_value: Word<T>,

    /// BabyBear range checker for the program counter.
    pub pc_range_checker: BabyBearWordRangeChecker<T>,

    /// The AUIPC nonce for the ADD operation.
    pub auipc_nonce: T,
}
