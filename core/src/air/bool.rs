use core::borrow::{Borrow, BorrowMut};
use p3_air::AirBuilder;
use p3_field::Field;

use super::AirVariable;
use valida_derive::AlignedBorrow;

/// An AIR representation of a boolean value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, AlignedBorrow)]
pub struct Bool<T>(pub T);

impl<T> AirVariable<T> for Bool<T> {
    fn eval_is_valid<AB: AirBuilder>(self, builder: &mut AB)
    where
        T: Into<AB::Expr>,
    {
        builder.assert_bool(self.0);
    }

    fn eval_is_equal<AB: AirBuilder>(self, other: Self, builder: &mut AB)
    where
        T: Into<AB::Expr>,
    {
        builder.assert_eq(self.0, other.0);
    }
}

impl<F: Field> From<bool> for Bool<F> {
    fn from(value: bool) -> Self {
        Self(F::from_canonical_u8(value as u8))
    }
}
