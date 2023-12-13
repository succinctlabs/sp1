use core::borrow::{Borrow, BorrowMut};
use p3_air::AirBuilder;
use p3_field::AbstractField;

use super::AirVariable;
use valida_derive::AlignedBorrow;

/// An AIR representation of a boolean value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, AlignedBorrow)]
pub struct Bool<T>(pub T);

impl<AB: AirBuilder> AirVariable<AB> for Bool<AB::Var> {
    fn size_of() -> usize {
        1
    }

    fn eval_is_valid(&self, builder: &mut AB) {
        builder.assert_zero(self.0 * (self.0 - AB::F::one()));
    }
}
