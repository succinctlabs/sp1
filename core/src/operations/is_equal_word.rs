use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_air::AirBuilder;
use p3_field::Field;
use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::air::WORD_SIZE;

use super::IsZeroOperation;
use super::IsZeroWordOperation;

/// A set of columns needed to compute the add of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsEqualWordOperation<T> {
    /// A word whose limbs are the difference between the limbs of the two inputs. For each `i`,
    /// `diff[i] = a[i] - b[i]`.
    pub diff: Word<T>,

    /// The result of whether `diff` is 0. `is_diff_zero.result` indicates whether the two input
    /// values are exactly equal.
    pub is_diff_zero: IsZeroWordOperation<T>,
}

impl<F: Field> IsEqualWordOperation<F> {
    pub fn populate(&mut self, a_u32: u32, b_u32: u32) -> u32 {
        let a = a_u32.to_le_bytes();
        let b = b_u32.to_le_bytes();
        for i in 0..WORD_SIZE {
            self.diff[i] = F::from_canonical_u8(a[i]) - F::from_canonical_u8(b[i]);
        }
        self.is_diff_zero.populate_from_field_element(self.diff);
        (a_u32 == b_u32) as u32
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: IsEqualWordOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        builder.assert_bool(is_real);

        // Calculate the difference in limbs.
        for i in 0..WORD_SIZE {
            builder.when(is_real).assert_eq(cols.diff[i], a[i] - b[i]);
        }

        // Check if a - b is 0.
        IsZeroWordOperation::<AB::F>::eval(builder, cols.diff, cols.is_diff_zero, is_real);

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(is_real * is_real * is_real - is_real * is_real * is_real);
    }
}
