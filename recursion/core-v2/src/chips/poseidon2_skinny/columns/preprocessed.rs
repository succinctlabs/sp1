use sp1_derive::AlignedBorrow;

use crate::chips::{mem::MemoryAccessCols, poseidon2_skinny::WIDTH};

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RoundCountersPreprocessedCols<T: Copy> {
    pub is_input_round: T,
    pub is_external_round: T,
    pub is_internal_round: T,
    pub round_constants: [T; WIDTH],
}

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedCols<T: Copy> {
    pub memory_preprocessed: [MemoryAccessCols<T>; WIDTH],
    pub round_counters_preprocessed: RoundCountersPreprocessedCols<T>,
}
