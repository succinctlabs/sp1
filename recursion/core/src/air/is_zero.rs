//! An operation to check if the input is 0.
//!
//! This is guaranteed to return 1 if and only if the input is 0.
//!
//! The idea is that 1 - input * inverse is exactly the boolean value indicating whether the input
//! is 0.
use p3_air::AirBuilder;
use p3_field::AbstractField;
use p3_field::Field;
use sp1_derive::AlignedBorrow;

use sp1_core::air::SP1AirBuilder;

/// A set of columns needed to compute whether the given word is 0.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsZeroOperation<T> {
    /// The inverse of the input.
    pub inverse: T,

    /// Result indicating whether the input is 0. This equals `inverse * input == 0`.
    pub result: T,
}

impl<F: Field> IsZeroOperation<F> {
    pub fn populate(&mut self, a: F) -> F {
        let (inverse, result) = if a.is_zero() {
            (F::zero(), F::one())
        } else {
            (a.inverse(), F::zero())
        };

        self.inverse = inverse;
        self.result = result;

        let prod = inverse * a;
        debug_assert!(prod == F::one() || prod.is_zero());

        result
    }
}

impl<F: Field> IsZeroOperation<F> {
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: AB::Expr,
        cols: IsZeroOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        // Assert that the `is_real` is a boolean.
        builder.assert_bool(is_real.clone());
        // Assert that the result is boolean.
        builder.when(is_real.clone()).assert_bool(cols.result);

        // 1. Input == 0 => is_zero = 1 regardless of the inverse.
        // 2. Input != 0
        //   2.1. inverse is correctly set => is_zero = 0.
        //   2.2. inverse is incorrect
        //     2.2.1 inverse is nonzero => is_zero isn't bool, it fails.
        //     2.2.2 inverse is 0 => is_zero is 1. But then we would assert that a = 0. And that
        //                           assert fails.

        // If the input is 0, then any product involving it is 0. If it is nonzero and its inverse
        // is correctly set, then the product is 1.

        let one = AB::Expr::one();
        let inverse = cols.inverse;

        let is_zero = one.clone() - inverse * a.clone();

        builder
            .when(is_real.clone())
            .assert_eq(is_zero, cols.result);

        builder.when(is_real.clone()).assert_bool(cols.result);

        // If the result is 1, then the input is 0.
        builder
            .when(is_real.clone())
            .when(cols.result)
            .assert_zero(a.clone());
    }
}
