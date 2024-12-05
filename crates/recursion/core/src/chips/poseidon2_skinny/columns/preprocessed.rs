use sp1_derive::AlignedBorrow;

use crate::chips::{mem::MemoryAccessColsChips, poseidon2_skinny::WIDTH};

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
pub struct Poseidon2PreprocessedColsSkinny<T: Copy> {
    pub memory_preprocessed: [MemoryAccessColsChips<T>; WIDTH],
    pub round_counters_preprocessed: RoundCountersPreprocessedCols<T>,
}

pub type Poseidon2PreprocessedCols<T> = Poseidon2PreprocessedColsSkinny<T>;
