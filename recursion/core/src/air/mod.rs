use core::mem::size_of;
use sp1_derive::AlignedBorrow;

#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Word<T>(pub [T; 4]);
