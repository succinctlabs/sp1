use std::mem::size_of;

use p3_air::{Air, BaseAir};
use sp1_derive::AlignedBorrow;

use crate::stark::SP1AirBuilder;

pub(crate) const NUM_MEMORY_LOCAL_COLS: usize = size_of::<MemoryLocalCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryLocalCols<T> {
    /// The timestamp of the memory access.
    pub timestamp: T,

    /// The address of the memory access.
    pub addr: T,

    /// Value of the memory access.
    pub value: T,
}

/// A memory chip that can initialize or finalize values in memory.
pub struct MemoryLocalChip {}

impl<F> BaseAir<F> for MemoryLocalChip {
    fn width(&self) -> usize {
        NUM_MEMORY_LOCAL_COLS
    }
}

impl<AB> Air<AB> for MemoryLocalChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, _builder: &mut AB) {}
}
