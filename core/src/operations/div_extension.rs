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
use crate::air::DEGREE;

/// A set of columns needed to compute whether the given word is 0.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct DivExtOperation<T> {
    /// Result is the quotient
    pub result: Extension<T>,
}

impl<F: BinomiallyExtendable<DEGREE>> DivExtOperation<F> {
    pub fn populate(
        &mut self,
        a: BinomialExtensionField<F, DEGREE>,
        b: BinomialExtensionField<F, DEGREE>,
    ) -> BinomialExtensionField<F, DEGREE> {
        let result = a / b;
        self.result = result.into();
        result
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Extension<AB::Expr>,
        b: Extension<AB::Expr>,
        cols: DivExtOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        let product = b.mul(&cols.result);
        builder.when(is_real.clone()).assert_eq(product, a);

        // If the result is 1, then the input is 0.
        builder
            .when(is_real.clone())
            .when(cols.result)
            .assert_zero(a.clone());
    }
}
