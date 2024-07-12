use sp1_derive::AlignedBorrow;

use crate::{mem::MemoryPreprocessedCols, poseidon2_wide::WIDTH};

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2MemoryPreprocessedCols<T: Copy> {
    pub memory_prepr: [MemoryPreprocessedCols<T>; WIDTH],
}

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RoundCountersPreprocessedCols<T: Copy> {
    pub is_external_round: T,
    pub is_internal_round: T,
    pub is_first_round: T,
    pub round_constants: [T; WIDTH],
}

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedCols<T: Copy> {
    pub memory_preprocessed: Poseidon2MemoryPreprocessedCols<T>,
    pub round_counters_preprocessed: RoundCountersPreprocessedCols<T>,
}
