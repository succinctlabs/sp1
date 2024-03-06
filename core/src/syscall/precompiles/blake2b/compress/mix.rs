use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;

use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::air::{SP1AirBuilder, WordU64};
use crate::operations::{AddOperationU64, FixedRotateRightOperationU64, XorOperationU64};
use crate::runtime::ExecutionRecord;

use super::mix;
use super::{MIX_INPUT_SIZE, STATE_SIZE};
/// A set of columns needed to compute the `mix` of the input state.
///  ``` ignore
/// fn mix(a: u64, b: u64, c: u64, d: u64, x: u64, y: u64) {
///     a = a.wrapping_add(b).wrapping_add(x);
///     d = (d ^ a).rotate_right(32);
///     c = c.wrapping_add(d);
///     b = (b ^ c).rotate_right(24);
///     a = a.wrapping_add(b).wrapping_add(y);
///     d = (d ^ a).rotate_right(16);
///     c = c.wrapping_add(d);
///     b = (b ^ c).rotate_right(63);
/// }
///  ```
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MixOperation<T> {
    pub a_plus_b: AddOperationU64<T>,
    pub a_plus_b_plus_x: AddOperationU64<T>,
    pub d_xor_a: XorOperationU64<T>,
    // Rotate right by 32 bits by just shifting bytes.
    pub c_plus_d: AddOperationU64<T>,
    pub b_xor_c: XorOperationU64<T>,
    // Rotate roght by 24 bits by just shifting bytes.
    pub a_plus_b_2: AddOperationU64<T>,
    pub a_plus_b_2_add_y: AddOperationU64<T>,
    pub d_xor_a_2: XorOperationU64<T>,
    // Rotate right by 16 bits by just shifting bytes.
    pub c_plus_d_2: AddOperationU64<T>,
    pub b_xor_c_2: XorOperationU64<T>,
    pub b_xor_c_2_rotate_right_63: FixedRotateRightOperationU64<T>,
}

impl<T: Copy> MixOperation<T> {
    /// Returns the results of the mix operation. The results are in the following order:
    /// a, b, c, d.
    /// a <- `a_plus_b_2_add_y` column
    /// b <- `b_xor_c_2_rotate_right_63` column
    /// c <- `c_plus_d_2` column
    /// d <- `d_xor_a_2` column (rotated right by 2 byte).
    pub fn results(&self) -> [WordU64<T>; STATE_SIZE] {
        let a = self.a_plus_b_2_add_y.value;
        let b = self.b_xor_c_2_rotate_right_63.value;
        let c = self.c_plus_d_2.value;
        let (d_hi, d_lo) = (self.d_xor_a_2.value_hi, self.d_xor_a_2.value_lo);
        let mut d = WordU64::from_u32_word(d_lo.value, d_hi.value);

        // Rotate right by 16 bits.
        d = WordU64([d[2], d[3], d[4], d[5], d[6], d[7], d[0], d[1]]);

        [a, b, c, d]
    }
}

impl<F: Field> MixOperation<F> {
    pub fn populate(
        &mut self,
        record: &mut ExecutionRecord,
        input: [u64; MIX_INPUT_SIZE],
    ) -> [u64; STATE_SIZE] {
        let [mut a, mut b, mut c, mut d, x, y] = input;

        // First 4 steps.
        {
            // a = a + b + x.
            a = self.a_plus_b.populate(record, a, b);
            a = self.a_plus_b_plus_x.populate(record, a, x);

            // d = (d ^ a).rotate_right(32).
            d = self.d_xor_a.populate(record, d, a);
            d = d.rotate_right(32);

            // c = c + d.
            c = self.c_plus_d.populate(record, c, d);

            // b = (b ^ c).rotate_right(24).
            b = self.b_xor_c.populate(record, b, c);
            b = b.rotate_right(24);
        }

        // Second 4 steps.
        {
            // a = a + b + y.
            a = self.a_plus_b_2.populate(record, a, b);
            a = self.a_plus_b_2_add_y.populate(record, a, y);

            // d = (d ^ a).rotate_right(16).
            d = self.d_xor_a_2.populate(record, d, a);
            d = d.rotate_right(16);

            // c = c + d.
            c = self.c_plus_d_2.populate(record, c, d);

            // b = (b ^ c).rotate_right(63).
            b = self.b_xor_c_2.populate(record, b, c);
            b = self.b_xor_c_2_rotate_right_63.populate(record, b, 63);
        }

        let result = [a, b, c, d];
        assert_eq!(result, mix(input));
        result
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        input: [WordU64<AB::Var>; MIX_INPUT_SIZE],
        cols: MixOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        let [mut a, mut b, mut c, mut d, x, y] = input;

        // First 4 steps.
        {
            // a = a + b + x.
            AddOperationU64::<AB::F>::eval(builder, a, b, cols.a_plus_b, is_real);
            a = cols.a_plus_b.value;
            AddOperationU64::<AB::F>::eval(builder, a, x, cols.a_plus_b_plus_x, is_real);
            a = cols.a_plus_b_plus_x.value;

            // d = (d ^ a).rotate_right(32).
            XorOperationU64::<AB::F>::eval(builder, d, a, cols.d_xor_a, is_real);
            let (d_hi, d_lo) = (cols.d_xor_a.value_hi, cols.d_xor_a.value_lo);
            d = WordU64::from_u32_word(d_lo.value, d_hi.value);

            // Rotate right by 32 bits.
            d = WordU64([d[4], d[5], d[6], d[7], d[0], d[1], d[2], d[3]]);

            // c = c + d.
            AddOperationU64::<AB::F>::eval(builder, c, d, cols.c_plus_d, is_real);
            c = cols.c_plus_d.value;

            // b = (b ^ c).rotate_right(24).
            XorOperationU64::<AB::F>::eval(builder, b, c, cols.b_xor_c, is_real);
            let (b_hi, b_lo) = (cols.b_xor_c.value_hi, cols.b_xor_c.value_lo);
            b = WordU64::from_u32_word(b_lo.value, b_hi.value);

            // Rotate right by 24 bits.
            b = WordU64([b[3], b[4], b[5], b[6], b[7], b[0], b[1], b[2]]);
        }

        //  Second 4 steps.
        {
            // a = a + b + y.
            AddOperationU64::<AB::F>::eval(builder, a, b, cols.a_plus_b_2, is_real);
            a = cols.a_plus_b_2.value;
            AddOperationU64::<AB::F>::eval(builder, a, y, cols.a_plus_b_2_add_y, is_real);
            a = cols.a_plus_b_2_add_y.value;

            // d = (d ^ a).rotate_right(16).
            XorOperationU64::<AB::F>::eval(builder, d, a, cols.d_xor_a_2, is_real);
            let (d_hi, d_lo) = (cols.d_xor_a_2.value_hi, cols.d_xor_a_2.value_lo);
            d = WordU64::from_u32_word(d_lo.value, d_hi.value);

            // Rotate right by 16 bits.
            d = WordU64([d[2], d[3], d[4], d[5], d[6], d[7], d[0], d[1]]);

            // c = c + d.
            AddOperationU64::<AB::F>::eval(builder, c, d, cols.c_plus_d_2, is_real);
            c = cols.c_plus_d_2.value;

            // b = (b ^ c).rotate_right(63).
            XorOperationU64::<AB::F>::eval(builder, b, c, cols.b_xor_c_2, is_real);
            let (b_hi, b_lo) = (cols.b_xor_c_2.value_hi, cols.b_xor_c_2.value_lo);
            b = WordU64::from_u32_word(b_lo.value, b_hi.value);
            FixedRotateRightOperationU64::<AB::F>::eval(
                builder,
                b,
                63,
                cols.b_xor_c_2_rotate_right_63,
                is_real,
            );
        }

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(is_real * is_real * is_real - is_real * is_real * is_real);
    }
}
