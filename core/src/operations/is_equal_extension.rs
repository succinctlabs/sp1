use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::extension::BinomialExtensionField;
use p3_field::extension::BinomiallyExtendable;
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::air::Extension;
use crate::air::SP1AirBuilder;
use crate::air::DEGREE;

use super::IsZeroExtOperation;

/// A set of columns needed to compute the equality of two field extension elements.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsEqualExtOperation<T> {
    /// An operation to check whether the differences in field extension elements is zero.
    pub is_diff_zero: IsZeroExtOperation<T>,
}

impl<F: BinomiallyExtendable<DEGREE>> IsEqualExtOperation<F> {
    pub fn populate(
        &mut self,
        a: BinomialExtensionField<F, DEGREE>,
        b: BinomialExtensionField<F, DEGREE>,
    ) -> u32 {
        let diff = a - b;
        self.is_diff_zero.populate(diff);
        (a == b) as u32
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Extension<AB::Expr>,
        b: Extension<AB::Expr>,
        cols: IsEqualExtOperation<AB::Var>,
        is_real: AB::Expr,
    ) where
        AB::F: BinomiallyExtendable<DEGREE>,
    {
        builder.assert_bool(is_real.clone());

        // Calculate differences.
        let diff = a.sub::<AB>(&b);

        // Check if the difference is 0.
        IsZeroExtOperation::<AB::F>::eval(builder, diff, cols.is_diff_zero, is_real.clone());

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(
            is_real.clone() * is_real.clone() * is_real.clone()
                - is_real.clone() * is_real.clone() * is_real.clone(),
        );
    }
}
