mod extension;

pub use extension::*;

use p3_field::AbstractField;
use p3_field::PrimeField32;
use sp1_core::air::{BinomialExtension, SP1AirBuilder};
use sp1_derive::AlignedBorrow;

/// The smallest unit of memory that can be read and written to.
#[derive(AlignedBorrow, Clone, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Block<T>(pub [T; 4]);

impl<F: PrimeField32> Block<F> {
    pub fn from(value: F) -> Self {
        Self([value, F::zero(), F::zero(), F::zero()])
    }
}

impl<T: Clone> Block<T> {
    pub fn as_extension<AB: SP1AirBuilder<Var = T>>(&self) -> BinomialExtension<AB::Expr> {
        let arr: [AB::Expr; 4] = self.0.clone().map(|x| AB::Expr::zero() + x);
        BinomialExtension(arr)
    }
}
