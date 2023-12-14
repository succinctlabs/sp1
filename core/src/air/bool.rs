use core::borrow::{Borrow, BorrowMut};
use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};

use super::AirVariable;
use valida_derive::AlignedBorrow;

/// An AIR representation of a boolean value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, AlignedBorrow)]
pub struct Bool<T>(pub T);

impl<AB: AirBuilder> AirVariable<AB> for Bool<AB::Var> {
    fn size_of() -> usize {
        1
    }

    fn variables(&self) -> &[<AB as AirBuilder>::Var] {
        core::slice::from_ref(&self.0)
    }

    fn eval_is_valid(&self, builder: &mut AB) {
        builder.assert_zero(self.0 * (self.0 - AB::F::one()));
    }
}

impl<F: Field> From<bool> for Bool<F> {
    fn from(value: bool) -> Self {
        Self(F::from_canonical_u8(value as u8))
    }
}
