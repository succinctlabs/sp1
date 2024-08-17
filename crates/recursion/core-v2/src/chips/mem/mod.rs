pub mod constant;
pub mod variable;

pub use constant::MemoryChip as MemoryConstChip;
pub use variable::MemoryChip as MemoryVarChip;

use sp1_derive::AlignedBorrow;

use crate::Address;

/// Data describing in what manner to access a particular memory block.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryAccessCols<F: Copy> {
    /// The address to access.
    pub addr: Address<F>,
    /// The multiplicity which to read/write.
    /// "Positive" values indicate a write, and "negative" values indicate a read.
    pub mult: F,
}
