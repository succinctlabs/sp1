use std::ops::{Add, Mul, Sub};

use p3_air::AirBuilder;
use p3_field::AbstractField;

use super::AirVariable;

/// An AIR representation of a boolean value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Bool<T>(pub T);

impl<AB: AirBuilder> AirVariable<AB> for Bool<AB::Var> {
    fn size_of() -> usize {
        1
    }

    fn eval_is_valid(&self, builder: &mut AB) {
        builder.assert_zero(self.0 * (self.0 - AB::F::one()));
    }
}

impl<T, S, O> Mul<S> for Bool<T>
where
    T: Mul<S, Output = O>,
{
    type Output = O;

    fn mul(self, rhs: S) -> Self::Output {
        self.0 * rhs
    }
}

impl<T, S, O> Add<S> for Bool<T>
where
    T: Add<S, Output = O>,
{
    type Output = O;

    fn add(self, rhs: S) -> Self::Output {
        self.0 + rhs
    }
}

impl<T, S, O> Sub<S> for Bool<T>
where
    T: Sub<S, Output = O>,
{
    type Output = O;

    fn sub(self, rhs: S) -> Self::Output {
        self.0 - rhs
    }
}
