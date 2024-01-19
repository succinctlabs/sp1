use core::borrow::{Borrow, BorrowMut};
use p3_field::Field;
use std::mem::size_of;

use valida_derive::AlignedBorrow;

/// A boolean value represented in an AIR.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, AlignedBorrow)]
pub struct Bool<T>(pub T);

impl<F: Field> From<bool> for Bool<F> {
    fn from(value: bool) -> Self {
        Self(F::from_bool(value))
    }
}
