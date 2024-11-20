use sp1_derive::AlignedBorrow;

use crate::{
    chips::{mem::MemoryAccessColsChips, poseidon2_wide::WIDTH},
    Address,
};

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedColsWide<T: Copy> {
    pub input: [Address<T>; WIDTH],
    pub output: [MemoryAccessColsChips<T>; WIDTH],
    pub is_real_neg: T,
}

pub type Poseidon2PreprocessedCols<T> = Poseidon2PreprocessedColsWide<T>;
