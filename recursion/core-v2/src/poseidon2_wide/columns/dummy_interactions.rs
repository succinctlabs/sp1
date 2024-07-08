use sp1_derive::AlignedBorrow;

use crate::poseidon2_wide::WIDTH;

pub const EXTENSION_FIELD_DEGREE: usize = 4;

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct DummyInteractionCols<T: Copy> {
    pub dummy_interaction_trace: [T; WIDTH * EXTENSION_FIELD_DEGREE],
    pub accumulator: [T; EXTENSION_FIELD_DEGREE],
}
