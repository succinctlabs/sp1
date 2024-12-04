use sp1_core_machine::operations::poseidon2::WIDTH;
use sp1_derive::AlignedBorrow;

use crate::{chips::mem::MemoryAccessColsChips, Address};

/// A column layout for the preprocessed Poseidon2 AIR.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedColsWide<T: Copy> {
    pub input: [Address<T>; WIDTH],
    pub output: [MemoryAccessColsChips<T>; WIDTH],
    pub is_real_neg: T,
}
