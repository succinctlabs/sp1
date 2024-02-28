use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;

use sp1_derive::AlignedBorrow;
use std::mem::size_of;

use crate::air::WORD_SIZE;
use crate::air::{SP1AirBuilder, Word};
use crate::operations::{AddOperationU64, FixedRotateRightOperationU64, XorOperation};
use crate::runtime::ExecutionRecord;

use super::mix;
use super::{MIX_INPUT_SIZE, STATE_ELE_PER_CALL};
/// A set of columns needed to compute the `mix` of the input state.
///  ``` ignore
/// fn mix(state: &mut BlockWords, a: u64, b: u64, c: u64, d: u64, x: u64, y: u64) {
///     state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
///     state[d] = (state[d] ^ state[a]).rotate_right(32);
///     state[c] = state[c].wrapping_add(state[d]);
///     state[b] = (state[b] ^ state[c]).rotate_right(24);
///     state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
///     state[d] = (state[d] ^ state[a]).rotate_right(16);
///     state[c] = state[c].wrapping_add(state[d]);
///     state[b] = (state[b] ^ state[c]).rotate_right(63);
/// }
///  ```
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MixOperation<T> {
    pub a_plus_b: AddOperationU64<T>,
    pub a_plus_b_plus_x: AddOperationU64<T>,
    pub d_xor_a_lo: XorOperation<T>,
    pub d_xor_a_hi: XorOperation<T>,
    // Rotate right by 32 bits by just shifting bytes.
    pub c_plus_d: AddOperationU64<T>,
    pub b_xor_c_lo: XorOperation<T>,
    pub b_xor_c_hi: XorOperation<T>,
    // Rotate roght by 24 bits by just shifting bytes.
    pub a_plus_b_2: AddOperationU64<T>,
    pub a_plus_b_2_add_y: AddOperationU64<T>,
    pub d_xor_a_2_lo: XorOperation<T>,
    pub d_xor_a_2_hi: XorOperation<T>,
    // Rotate right by 16 bits by just shifting bytes.
    pub c_plus_d_2: AddOperationU64<T>,
    pub b_xor_c_2_lo: XorOperation<T>,
    pub b_xor_c_2_hi: XorOperation<T>,
    pub b_xor_c_2_rotate_right_63: FixedRotateRightOperationU64<T>,
    /// `state[a]`, `state[b]`, `state[c]`, `state[d]` after all the steps.
    pub result: [Word<T>; STATE_ELE_PER_CALL * 2],
}

impl<F: Field> MixOperation<F> {
    pub fn populate(&mut self, record: &mut ExecutionRecord, input: [u32; 12]) -> [u32; 8] {
        let mut a_lo = input[0];
        let mut a_hi = input[1];
        let mut b_lo = input[2];
        let mut b_hi = input[3];
        let mut c_lo = input[4];
        let mut c_hi = input[5];
        let mut d_lo = input[6];
        let mut d_hi = input[7];
        let x_lo = input[8];
        let x_hi = input[9];
        let y_lo = input[10];
        let y_hi = input[11];

        // the input in u64 later used to compare with the result of the mix function.
        let input_u64 = [
            (a_hi as u64) << 32 | a_lo as u64,
            (b_hi as u64) << 32 | b_lo as u64,
            (c_hi as u64) << 32 | c_lo as u64,
            (d_hi as u64) << 32 | d_lo as u64,
            (x_hi as u64) << 32 | x_lo as u64,
            (y_hi as u64) << 32 | y_lo as u64,
        ];

        // First 4 steps.
        {
            // a = a + b + x.
            (a_lo, a_hi) = self.a_plus_b.populate(record, a_lo, a_hi, b_lo, b_hi);
            (a_lo, a_hi) = self
                .a_plus_b_plus_x
                .populate(record, a_lo, a_hi, x_lo, x_hi);

            // d = (d ^ a).rotate_right(32).
            d_lo = self.d_xor_a_lo.populate(record, d_lo, a_lo);
            d_hi = self.d_xor_a_hi.populate(record, d_hi, a_hi);
            let d = (d_hi as u64) << 32 | d_lo as u64;
            let d = d.rotate_right(32);
            d_lo = d as u32;
            d_hi = (d >> 32) as u32;

            // c = c + d.
            (c_lo, c_hi) = self.c_plus_d.populate(record, c_lo, c_hi, d_lo, d_hi);

            // b = (b ^ c).rotate_right(24).
            b_lo = self.b_xor_c_lo.populate(record, b_lo, c_lo);
            b_hi = self.b_xor_c_hi.populate(record, b_hi, c_hi);
            let b = (b_hi as u64) << 32 | b_lo as u64;
            let b = b.rotate_right(24);
            b_lo = b as u32;
            b_hi = (b >> 32) as u32;
        }

        // Second 4 steps.
        {
            // a = a + b + y.
            (a_lo, a_hi) = self.a_plus_b_2.populate(record, a_lo, a_hi, b_lo, b_hi);
            (a_lo, a_hi) = self
                .a_plus_b_2_add_y
                .populate(record, a_lo, a_hi, y_lo, y_hi);

            // d = (d ^ a).rotate_right(16).
            d_lo = self.d_xor_a_2_lo.populate(record, d_lo, a_lo);
            d_hi = self.d_xor_a_2_hi.populate(record, d_hi, a_hi);
            let d = (d_hi as u64) << 32 | d_lo as u64;
            let d = d.rotate_right(16);
            d_lo = d as u32;
            d_hi = (d >> 32) as u32;

            // c = c + d.
            (c_lo, c_hi) = self.c_plus_d_2.populate(record, c_lo, c_hi, d_lo, d_hi);

            // b = (b ^ c).rotate_right(63).
            b_lo = self.b_xor_c_2_lo.populate(record, b_lo, c_lo);
            b_hi = self.b_xor_c_2_hi.populate(record, b_hi, c_hi);
            (b_lo, b_hi) = self
                .b_xor_c_2_rotate_right_63
                .populate(record, b_lo, b_hi, 63);
        }

        let result = [a_lo, a_hi, b_lo, b_hi, c_lo, c_hi, d_lo, d_hi];
        let result_u64 = [
            (result[1] as u64) << 32 | result[0] as u64,
            (result[3] as u64) << 32 | result[2] as u64,
            (result[5] as u64) << 32 | result[4] as u64,
            (result[7] as u64) << 32 | result[6] as u64,
        ];

        assert_eq!(result_u64, mix(input_u64));
        self.result = result.map(Word::from);
        result
    }

    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        input: [Word<AB::Var>; MIX_INPUT_SIZE * 2],
        cols: MixOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        builder.assert_bool(is_real);
        let mut a_lo = input[0];
        let mut a_hi = input[1];
        let mut b_lo = input[2];
        let mut b_hi = input[3];
        let mut c_lo = input[4];
        let mut c_hi = input[5];
        let mut d_lo = input[6];
        let mut d_hi = input[7];
        let x_lo = input[8];
        let x_hi = input[9];
        let y_lo = input[10];
        let y_hi = input[11];

        // First 4 steps.
        {
            // a = a + b + x.
            AddOperationU64::<AB::F>::eval(builder, a_lo, a_hi, b_lo, b_hi, cols.a_plus_b, is_real);
            (a_lo, a_hi) = (cols.a_plus_b.lo, cols.a_plus_b.hi);
            AddOperationU64::<AB::F>::eval(
                builder,
                a_lo,
                a_hi,
                x_lo,
                x_hi,
                cols.a_plus_b_plus_x,
                is_real,
            );
            (a_lo, a_hi) = (cols.a_plus_b_plus_x.lo, cols.a_plus_b_plus_x.hi);

            // d = (d ^ a).rotate_right(32).
            XorOperation::<AB::F>::eval(builder, d_lo, a_lo, cols.d_xor_a_lo, is_real);
            d_lo = cols.d_xor_a_lo.value;
            XorOperation::<AB::F>::eval(builder, d_hi, a_hi, cols.d_xor_a_hi, is_real);
            d_hi = cols.d_xor_a_hi.value;
            // Rotate right by 32 bits.
            (d_lo, d_hi) = (d_hi, d_lo);

            // c = c + d.
            AddOperationU64::<AB::F>::eval(builder, c_lo, c_hi, d_lo, d_hi, cols.c_plus_d, is_real);
            (c_lo, c_hi) = (cols.c_plus_d.lo, cols.c_plus_d.hi);

            // b = (b ^ c).rotate_right(24).
            XorOperation::<AB::F>::eval(builder, b_lo, c_lo, cols.b_xor_c_lo, is_real);
            b_lo = cols.b_xor_c_lo.value;
            XorOperation::<AB::F>::eval(builder, b_hi, c_hi, cols.b_xor_c_hi, is_real);
            b_hi = cols.b_xor_c_hi.value;
            // Rotate right by 24 bits.
            let temp_b_hi = b_hi;
            b_hi = Word([b_hi[3], b_lo[0], b_lo[1], b_lo[2]]);
            b_lo = Word([b_lo[3], temp_b_hi[0], temp_b_hi[1], temp_b_hi[2]]);
        }

        //  Second 4 steps.
        {
            // a = a + b + y.
            AddOperationU64::<AB::F>::eval(
                builder,
                a_lo,
                a_hi,
                b_lo,
                b_hi,
                cols.a_plus_b_2,
                is_real,
            );
            (a_lo, a_hi) = (cols.a_plus_b_2.lo, cols.a_plus_b_2.hi);
            AddOperationU64::<AB::F>::eval(
                builder,
                a_lo,
                a_hi,
                y_lo,
                y_hi,
                cols.a_plus_b_2_add_y,
                is_real,
            );
            (a_lo, a_hi) = (cols.a_plus_b_2_add_y.lo, cols.a_plus_b_2_add_y.hi);

            // d = (d ^ a).rotate_right(16).
            XorOperation::<AB::F>::eval(builder, d_lo, a_lo, cols.d_xor_a_2_lo, is_real);
            d_lo = cols.d_xor_a_2_lo.value;
            XorOperation::<AB::F>::eval(builder, d_hi, a_hi, cols.d_xor_a_2_hi, is_real);
            d_hi = cols.d_xor_a_2_hi.value;
            // Rotate right by 16 bits.
            let temp_d_hi = d_hi;
            d_hi = Word([d_hi[2], d_hi[3], d_lo[0], d_lo[1]]);
            d_lo = Word([d_lo[2], d_lo[3], temp_d_hi[0], temp_d_hi[1]]);

            // c = c + d.
            AddOperationU64::<AB::F>::eval(
                builder,
                c_lo,
                c_hi,
                d_lo,
                d_hi,
                cols.c_plus_d_2,
                is_real,
            );
            (c_lo, c_hi) = (cols.c_plus_d_2.lo, cols.c_plus_d_2.hi);

            // b = (b ^ c).rotate_right(63).
            XorOperation::<AB::F>::eval(builder, b_lo, c_lo, cols.b_xor_c_2_lo, is_real);
            b_lo = cols.b_xor_c_2_lo.value;
            XorOperation::<AB::F>::eval(builder, b_hi, c_hi, cols.b_xor_c_2_hi, is_real);
            b_hi = cols.b_xor_c_2_hi.value;
            FixedRotateRightOperationU64::<AB::F>::eval(
                builder,
                b_lo,
                b_hi,
                63,
                cols.b_xor_c_2_rotate_right_63,
                is_real,
            );
            (b_lo, b_hi) = (
                cols.b_xor_c_2_rotate_right_63.lo,
                cols.b_xor_c_2_rotate_right_63.hi,
            );
        }

        let results = [a_lo, a_hi, b_lo, b_hi, c_lo, c_hi, d_lo, d_hi];
        for i in 0..results.len() {
            for j in 0..WORD_SIZE {
                builder.assert_eq(cols.result[i][j], results[i][j]);
            }
        }
        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(
            a_lo[0] * b_lo[0] * cols.a_plus_b.lo[0] - a_lo[0] * b_lo[0] * cols.a_plus_b.lo[0],
        );
    }
}
