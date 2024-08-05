pub mod constant;
pub mod variable;

pub use constant::MemoryChip as MemoryConstChip;
pub use variable::MemoryChip as MemoryVarChip;

use sp1_derive::AlignedBorrow;

use crate::Address;

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryAccessCols<F: Copy> {
    pub addr: Address<F>,
    pub write_mult: F,
}
