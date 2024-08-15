//! An operation to check if the input word is 0.
//!
//! This is bijective (i.e., returns 1 if and only if the input is 0). It is also worth noting that
//! this operation doesn't do a range check.
use p3_air::AirBuilder;
use p3_field::Field;
use sp1_derive::AlignedBorrow;
use sp1_primitives::consts::WORD_SIZE;
use sp1_stark::{air::SP1AirBuilder, Word};

use super::IsZeroOperation;

/// A set of columns needed to compute whether the given word is 0.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsZeroWordOperation<T> {
    /// `IsZeroOperation` to check if each byte in the input word is zero.
    pub is_zero_byte: [IsZeroOperation<T>; WORD_SIZE],

    /// A boolean flag indicating whether the lower word (the bottom 16 bits of the input) is 0.
    /// This equals `is_zero_byte[0] * is_zero_byte[1]`.
    pub is_lower_half_zero: T,

    /// A boolean flag indicating whether the upper word (the top 16 bits of the input) is 0. This
    /// equals `is_zero_byte[2] * is_zero_byte[3]`.
    pub is_upper_half_zero: T,

    /// A boolean flag indicating whether the word is zero. This equals `is_zero_byte[0] * ... *
    /// is_zero_byte[WORD_SIZE - 1]`.
    pub result: T,
}

impl<F: Field> IsZeroWordOperation<F> {
    pub fn populate(&mut self, a_u32: u32) -> u32 {
        self.populate_from_field_element(Word::from(a_u32))
    }

    pub fn populate_from_field_element(&mut self, a: Word<F>) -> u32 {
        let mut is_zero = true;
        for i in 0..WORD_SIZE {
            is_zero &= self.is_zero_byte[i].populate_from_field_element(a[i]) == 1;
        }
        self.is_lower_half_zero = self.is_zero_byte[0].result * self.is_zero_byte[1].result;
        self.is_upper_half_zero = self.is_zero_byte[2].result * self.is_zero_byte[3].result;
        self.result = F::from_bool(is_zero);
        is_zero as u32
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Word<AB::Expr>,
        cols: IsZeroWordOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        // Calculate whether each byte is 0.
        for i in 0..WORD_SIZE {
            IsZeroOperation::<AB::F>::eval(
                builder,
                a[i].clone(),
                cols.is_zero_byte[i],
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
            cols.is_zero_byte[0].result * cols.is_zero_byte[1].result,
        );
        builder_is_real.assert_eq(
            cols.is_upper_half_zero,
            cols.is_zero_byte[2].result * cols.is_zero_byte[3].result,
        );
        builder_is_real.assert_eq(cols.result, cols.is_lower_half_zero * cols.is_upper_half_zero);
    }
}
