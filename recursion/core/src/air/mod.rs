use core::mem::size_of;
use p3_field::PrimeField32;
use sp1_derive::AlignedBorrow;

#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Word<T>(pub [T; 4]);

impl<F: PrimeField32> Word<F> {
    pub fn from(value: F) -> Self {
        Self([value, F::zero(), F::zero(), F::zero()])
    }
}
