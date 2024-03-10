use p3_field::AbstractField;
use p3_field::PrimeField32;
use sp1_core::air::{Extension, SP1AirBuilder};
use sp1_derive::AlignedBorrow;

#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Word<T>(pub [T; 4]);

impl<F: PrimeField32> Word<F> {
    pub fn from(value: F) -> Self {
        Self([value, F::zero(), F::zero(), F::zero()])
    }
}

impl<T: Clone> Word<T> {
    pub fn extension<AB: SP1AirBuilder<Var = T>>(&self) -> Extension<AB::Expr> {
        let arr: [AB::Expr; 4] = self.0.clone().map(|x| AB::Expr::zero() + x);
        Extension(arr)
    }
}
