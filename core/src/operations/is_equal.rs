use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;
use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;

use super::IsZeroOperation;

/// A set of columns needed to compute the equality of two values.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsEqualOperation<T> {
    /// The result of whether `diff` is 0. `is_diff_zero.result` indicates whether the two input
    /// values are exactly equal.
    pub is_diff_zero: IsZeroOperation<T>,
}

impl<F: Field> IsEqualOperation<F> {
    pub fn populate(&mut self, a_u32: u32, b_u32: u32) -> u32 {
        let a = F::from_canonical_u32(a_u32);
        let b = F::from_canonical_u32(b_u32);
        self.is_diff_zero.populate_from_field_element(a - b);
        (a_u32 == b_u32) as u32
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        a: AB::Expr,
        b: AB::Expr,
        cols: IsEqualOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        // Check if a - b is 0.
        IsZeroOperation::<AB::F>::eval(builder, a.clone() - b.clone(), cols.is_diff_zero, is_real);

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(a.clone() * a.clone() * a.clone() - b.clone() * b.clone() * b.clone());
    }
}
