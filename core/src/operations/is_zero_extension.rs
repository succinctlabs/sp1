//! An operation to check if the input word is 0.
//!
//! This is bijective (i.e., returns 1 if and only if the input is 0). It is also worth noting that
//! this operation doesn't do a range check.
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_air::AirBuilder;
use p3_field::extension::BinomialExtensionField;
use p3_field::extension::BinomiallyExtendable;
use p3_field::AbstractExtensionField;
use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::air::Extension;
use crate::air::SP1AirBuilder;
use crate::air::DEGREE;

use super::IsZeroOperation;

/// A set of columns needed to compute whether the given field ext element is 0.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsZeroExtOperation<T> {
    /// `IsZeroOperation` to check if each base field element in the input field ext element is zero.
    pub is_zero_base_element: [IsZeroOperation<T>; DEGREE],

    /// A boolean flag indicating whether the first and second base field elements are 0.
    /// This equals `is_zero_byte[0] * is_zero_byte[1]`.
    pub is_lower_half_zero: T,

    /// A boolean flag indicating whether the third and fourth base field elements are 0.
    pub is_upper_half_zero: T,

    /// A boolean flag indicating whether the field ext element is zero. This equals `is_zero_byte[0] * ... *
    /// is_zero_byte[DEGREE - 1]`.
    pub result: T,
}

impl<F: BinomiallyExtendable<DEGREE>> IsZeroExtOperation<F> {
    pub fn populate(&mut self, a: BinomialExtensionField<F, DEGREE>) -> u32 {
        let mut is_zero = true;
        let base_slice = a.as_base_slice();
        for i in 0..DEGREE {
            is_zero &= self.is_zero_base_element[i].populate_from_field_element(base_slice[i]) == 1;
        }
        self.is_lower_half_zero =
            self.is_zero_base_element[0].result * self.is_zero_base_element[1].result;
        self.is_upper_half_zero =
            self.is_zero_base_element[2].result * self.is_zero_base_element[3].result;
        self.result = F::from_bool(is_zero);
        is_zero as u32
    }
}

impl<T> IsZeroExtOperation<T> {
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Extension<AB::Expr>,
        cols: IsZeroExtOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        let base_slice = a.as_base_slice();

        // Calculate whether each byte is 0.
        for i in 0..DEGREE {
            IsZeroOperation::<AB::F>::eval(
                builder,
                base_slice[i].clone(),
                cols.is_zero_base_element[i],
                is_real.clone(),
            );
        }

        // From here, we only assert when is_real is true.
        builder.assert_bool(is_real.clone());
        let mut builder_is_real = builder.when(is_real.clone());

        // Calculate is_upper_half_zero and is_lower_half_zero and finally the result.
        builder_is_real.assert_bool(cols.is_lower_half_zero);
        builder_is_real.assert_bool(cols.is_upper_half_zero);
        builder_is_real.assert_bool(cols.result);
        builder_is_real.assert_eq(
            cols.is_lower_half_zero,
            cols.is_zero_base_element[0].result * cols.is_zero_base_element[1].result,
        );
        builder_is_real.assert_eq(
            cols.is_upper_half_zero,
            cols.is_zero_base_element[2].result * cols.is_zero_base_element[3].result,
        );
        builder_is_real.assert_eq(
            cols.result,
            cols.is_lower_half_zero * cols.is_upper_half_zero,
        );
    }
}
