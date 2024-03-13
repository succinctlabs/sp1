mod extension;

pub use extension::*;

use p3_field::AbstractField;
use p3_field::PrimeField32;
use sp1_core::air::{BinomialExtension, SP1AirBuilder};
use sp1_derive::AlignedBorrow;

/// The smallest unit of memory that can be read and written to.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Block<T>(pub [T; 4]);

impl<T: Clone> Block<T> {
    pub fn as_extension<AB: SP1AirBuilder<Var = T>>(&self) -> BinomialExtension<AB::Expr> {
        let arr: [AB::Expr; 4] = self.0.clone().map(|x| AB::Expr::zero() + x);
        BinomialExtension(arr)
    }
}

impl<T> From<[T; 4]> for Block<T> {
    fn from(arr: [T; 4]) -> Self {
        Self(arr)
    }
}

impl<F: PrimeField32> From<F> for Block<F> {
    fn from(value: F) -> Self {
        Self([value, F::zero(), F::zero(), F::zero()])
    }
}

impl<T: Copy> From<&[T]> for Block<T> {
    fn from(slice: &[T]) -> Self {
        let arr: [T; 4] = slice.try_into().unwrap();
        Self(arr)
    }
}
