use sp1_derive::AlignedBorrow;

use crate::{
    chips::{mem::MemoryAccessCols, poseidon2_wide::WIDTH},
    Address,
};

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedCols<T: Copy> {
    pub input: [Address<T>; WIDTH],
    pub output: [MemoryAccessCols<T>; WIDTH],
    pub is_real_neg: T,
}
