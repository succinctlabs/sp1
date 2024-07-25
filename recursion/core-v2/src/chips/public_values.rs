use p3_air::BaseAir;
use sp1_derive::AlignedBorrow;

use crate::DIGEST_SIZE;

use super::mem::MemoryAccessCols;

pub const NUM_PUBLIC_VALUES_COLS: usize = core::mem::size_of::<PublicValuesCols<u8>>();
pub const NUM_PUBLIC_VALUES_PREPROCESSED_COLS: usize =
    core::mem::size_of::<PublicValuesPreprocessedCols<u8>>();

#[derive(Default)]
pub struct PublicValuesChip<const DEGREE: usize> {}

/// The preprocessed columns for a FRI fold invocation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct PublicValuesPreprocessedCols<T: Copy> {
    pub pv_idx: [T; DIGEST_SIZE],
    pub pv_mem: MemoryAccessCols<T>,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct PublicValuesCols<T: Copy> {
    pub pv: T,
}

impl<F, const DEGREE: usize> BaseAir<F> for PublicValuesChip<DEGREE> {
    fn width(&self) -> usize {
        NUM_PUBLIC_VALUES_COLS
    }
}
