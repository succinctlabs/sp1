//! An operation to performce div on the inputs.
//!
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::extension::BinomialExtensionField;
use p3_field::extension::BinomiallyExtendable;
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::air::ExtAirBuilder;
use crate::air::Extension;
use crate::air::SP1AirBuilder;
use crate::air::DEGREE;

use super::IsEqualExtOperation;

/// A set of columns needed to compute whether the given word is 0.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct DivExtOperation<T> {
    pub is_equal: IsEqualExtOperation<T>,

    pub product: Extension<T>,

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

        let product = b * result;
        self.product = product.into();
        self.is_equal.populate(a, product);

        result
    }
}

impl<T> DivExtOperation<T> {
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Extension<AB::Expr>,
        b: Extension<AB::Expr>,
        cols: DivExtOperation<AB::Var>,
        is_real: AB::Expr,
    ) where
        AB::F: BinomiallyExtendable<4>,
    {
        builder.assert_bool(is_real.clone());

        let product = b.mul::<AB>(&cols.result.from_var::<AB>());
        builder
            .when(is_real.clone())
            .assert_ext_eq(product.clone(), Extension::from_var::<AB>(cols.product));

        IsEqualExtOperation::<AB::F>::eval(
            builder,
            a,
            Extension::from_var::<AB>(cols.product),
            cols.is_equal,
            is_real.clone(),
        );

        builder.assert_zero(
            is_real.clone() * is_real.clone() * is_real.clone()
                - is_real.clone() * is_real.clone() * is_real.clone(),
        );
    }
}
