use sp1_derive::AlignedBorrow;

use crate::chips::{mem::MemoryAccessCols, poseidon2_wide::WIDTH};

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedCols<T: Copy> {
    pub memory_preprocessed: [MemoryAccessCols<T>; 2 * WIDTH],
}
