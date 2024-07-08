use sp1_derive::AlignedBorrow;

use crate::mem::MemoryPreprocessedColsNoVal;
use crate::poseidon2_wide::WIDTH;

// pub const POSEIDON2_MEMORY_PREPROCESSED_WIDTH: usize = size_of::<MemoryPreprocessedkkj<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2MemoryPreprocessedCols<T: Copy> {
    pub memory_prepr: [MemoryPreprocessedColsNoVal<T>; WIDTH],
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
