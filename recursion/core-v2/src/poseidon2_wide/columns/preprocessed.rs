use sp1_derive::AlignedBorrow;

use crate::{mem::MemoryPreprocessedCols, poseidon2_wide::WIDTH};

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedCols<T: Copy> {
    pub memory_preprocessed: [MemoryPreprocessedCols<T>; 2 * WIDTH],
}
