use p3_field::Field;
use sp1_derive::AlignedBorrow;
use sp1_stark::{air::SP1AirBuilder, Word};

use super::IsZeroWordOperation;

/// A set of columns needed to compute the equality of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsEqualWordOperation<T> {
    /// An operation to check whether the differences in limbs are all 0 (i.e., `a[0] - b[0]`,
    /// `a[1] - b[1]`, `a[2] - b[2]`, `a[3] - b[3]]`). The result of `IsEqualWordOperation` is
    /// `is_diff_zero.result`.
    pub is_diff_zero: IsZeroWordOperation<T>,
}

impl<F: Field> IsEqualWordOperation<F> {
    pub fn populate(&mut self, a_u32: u32, b_u32: u32) -> u32 {
        let a = a_u32.to_le_bytes();
        let b = b_u32.to_le_bytes();
        let diff = Word([
            F::from_canonical_u8(a[0]) - F::from_canonical_u8(b[0]),
            F::from_canonical_u8(a[1]) - F::from_canonical_u8(b[1]),
            F::from_canonical_u8(a[2]) - F::from_canonical_u8(b[2]),
            F::from_canonical_u8(a[3]) - F::from_canonical_u8(b[3]),
        ]);
        self.is_diff_zero.populate_from_field_element(diff);
        (a_u32 == b_u32) as u32
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Word<AB::Expr>,
        b: Word<AB::Expr>,
        cols: IsEqualWordOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        // Calculate differences in limbs.
        let diff = Word([
            a[0].clone() - b[0].clone(),
            a[1].clone() - b[1].clone(),
            a[2].clone() - b[2].clone(),
            a[3].clone() - b[3].clone(),
        ]);

        // Check if the difference is 0.
        IsZeroWordOperation::<AB::F>::eval(builder, diff, cols.is_diff_zero, is_real.clone());
    }
}
