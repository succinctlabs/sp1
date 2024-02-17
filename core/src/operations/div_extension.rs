//! An operation to performce div on the inputs.
//!
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_air::AirBuilder;
use p3_field::extension::BinomialExtensionField;
use p3_field::extension::BinomiallyExtendable;
use p3_field::AbstractField;
use p3_field::Field;
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::air::Extension;
use crate::air::SP1AirBuilder;

/// A set of columns needed to compute whether the given word is 0.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct DivExtOperation<T> {
    /// The inverse of the b input
    pub b_inverse: Extension<T>,

    /// Result is the quotient
    pub result: Extension<T>,
}

impl<F: BinomiallyExtendable<4>> DivExtOperation<F> {
    pub fn populate(
        &mut self,
        a: BinomialExtensionField<F, 4>,
        b: BinomialExtensionField<F, 4>,
    ) -> BinomialExtensionField<F, 4> {
        self.b_inverse = b.inverse().into();
        let result = a / b;
        self.result = result.into();
        result
    }

    // pub fn eval<AB: SP1AirBuilder>(
    //     builder: &mut AB,
    //     a: AB::Expr,
    //     cols: DivExtOperation<AB::Var>,
    //     is_real: AB::Expr,
    // ) {
    //     builder.assert_bool(is_real.clone());
    //     let one: AB::Expr = AB::F::one().into();

    //     // 1. Input == 0 => is_zero = 1 regardless of the inverse.
    //     // 2. Input != 0
    //     //   2.1. inverse is correctly set => is_zero = 0.
    //     //   2.2. inverse is incorrect
    //     //     2.2.1 inverse is nonzero => is_zero isn't bool, it fails.
    //     //     2.2.2 inverse is 0 => is_zero is 1. But then we would assert that a = 0. And that
    //     //                           assert fails.

    //     // If the input is 0, then any product involving it is 0. If it is nonzero and its inverse
    //     // is correctly set, then the product is 1.
    //     let is_zero = one.clone() - cols.inverse * a.clone();
    //     builder
    //         .when(is_real.clone())
    //         .assert_eq(is_zero, cols.result);
    //     builder.when(is_real.clone()).assert_bool(cols.result);

    //     // If the result is 1, then the input is 0.
    //     builder
    //         .when(is_real.clone())
    //         .when(cols.result)
    //         .assert_zero(a.clone());
    // }
}
