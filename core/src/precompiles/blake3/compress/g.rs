use core::borrow::Borrow;
use core::borrow::BorrowMut;
use num::integer::Roots;
use p3_air::AirBuilder;
use p3_field::AbstractField;
use p3_field::Field;

use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::air::WORD_SIZE;
use crate::operations::AddOperation;
use crate::operations::FixedRotateRightOperation;
use crate::operations::XorOperation;
use crate::runtime::Segment;

use super::g_func;
/// A set of columns needed to compute the `g` of the input state.
///  ``` ignore
/// fn g(state: &mut BlockWords, a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
///     state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
///     state[d] = (state[d] ^ state[a]).rotate_right(16);
///     state[c] = state[c].wrapping_add(state[d]);
///     state[b] = (state[b] ^ state[c]).rotate_right(12);
///     state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
///     state[d] = (state[d] ^ state[a]).rotate_right(8);
///     state[c] = state[c].wrapping_add(state[d]);
///     state[b] = (state[b] ^ state[c]).rotate_right(7);
/// }
///  ```
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct GOperation<T> {
    pub state_a_plus_state_b: AddOperation<T>,
    pub state_a_plus_state_b_plus_x: AddOperation<T>,
    pub state_d_xor_state_a: XorOperation<T>,
    // Rotate right by 16 bits by just shifting bytes.
    pub state_c_plus_state_d: AddOperation<T>,
    pub state_b_xor_state_c: XorOperation<T>,
    pub state_b_xor_state_c_rotate_right_12: FixedRotateRightOperation<T>,
    pub state_a_plus_state_b_2: AddOperation<T>,
    pub state_a_plus_state_b_2_add_y: AddOperation<T>,
    // Rotate right by 8 bits by just shifting bytes.
    pub state_d_xor_state_a_2: XorOperation<T>,
    pub state_c_plus_state_d_2: AddOperation<T>,
    pub state_b_xor_state_c_2: XorOperation<T>,
    pub state_b_xor_state_c_2_rotate_right_7: FixedRotateRightOperation<T>,
    /// `state[a]`, `state[b]`, `state[c]`, `state[d]` after all the steps.
    pub result: [Word<T>; 4],
}

impl<F: Field> GOperation<F> {
    pub fn populate(&mut self, segment: &mut Segment, input: [u32; 6]) -> [u32; 4] {
        let mut state_a = input[0];
        let mut state_b = input[1];
        let mut state_c = input[2];
        let mut state_d = input[3];
        let x = input[4];
        let y = input[5];

        // First 4 steps.
        {
            state_a = self
                .state_a_plus_state_b
                .populate(segment, state_a, state_b);
            state_a = self
                .state_a_plus_state_b_plus_x
                .populate(segment, state_a, x);

            state_d = self.state_d_xor_state_a.populate(segment, state_d, state_a);
            state_d = state_d.rotate_right(16);

            state_c = self
                .state_c_plus_state_d
                .populate(segment, state_c, state_d);

            state_b = self.state_b_xor_state_c.populate(segment, state_b, state_c);
            state_b = self
                .state_b_xor_state_c_rotate_right_12
                .populate(segment, state_b, 12);
        }

        // Second 4 steps.
        {
            state_a = self
                .state_a_plus_state_b_2
                .populate(segment, state_a, state_b);
            state_a = self
                .state_a_plus_state_b_2_add_y
                .populate(segment, state_a, y);

            state_d = self
                .state_d_xor_state_a_2
                .populate(segment, state_d, state_a);
            state_d = state_d.rotate_right(8);

            state_c = self
                .state_c_plus_state_d_2
                .populate(segment, state_c, state_d);

            state_b = self
                .state_b_xor_state_c_2
                .populate(segment, state_b, state_c);
            state_b = self
                .state_b_xor_state_c_2_rotate_right_7
                .populate(segment, state_b, 7);
        }

        assert_eq!([state_a, state_b, state_c, state_d], g_func(input));
        [state_a, state_b, state_c, state_d]
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        input: [Word<AB::Var>; 6],
        cols: GOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        let mut a = input[0];
        let mut b = input[1];
        let mut c = input[2];
        let mut d = input[3];
        let x = input[4];
        let y = input[5];

        // First 4 steps.
        {
            AddOperation::<AB::F>::eval(builder, a, b, cols.state_a_plus_state_b, is_real);
            a = cols.state_a_plus_state_b.value;
            AddOperation::<AB::F>::eval(builder, a, x, cols.state_a_plus_state_b_plus_x, is_real);
            a = cols.state_a_plus_state_b_plus_x.value;

            XorOperation::<AB::F>::eval(builder, d, a, cols.state_d_xor_state_a, is_real);
            d = cols.state_d_xor_state_a.value;

            // Rotate right by 16 bits.
            d = Word([d[1], d[0], d[3], d[2]]);

            AddOperation::<AB::F>::eval(builder, c, d, cols.state_c_plus_state_d, is_real);
            c = cols.state_c_plus_state_d.value;

            XorOperation::<AB::F>::eval(builder, b, c, cols.state_b_xor_state_c, is_real);
            b = cols.state_b_xor_state_c.value;
            FixedRotateRightOperation::<AB::F>::eval(
                builder,
                b,
                12,
                cols.state_b_xor_state_c_rotate_right_12,
                is_real,
            );
            b = cols.state_b_xor_state_c_rotate_right_12.value;
        }

        // Second 4 steps.
        {
            AddOperation::<AB::F>::eval(builder, a, b, cols.state_a_plus_state_b_2, is_real);
            a = cols.state_a_plus_state_b_2.value;
            AddOperation::<AB::F>::eval(builder, a, y, cols.state_a_plus_state_b_2_add_y, is_real);
            a = cols.state_a_plus_state_b_2_add_y.value;

            XorOperation::<AB::F>::eval(builder, d, a, cols.state_d_xor_state_a_2, is_real);
            d = cols.state_d_xor_state_a_2.value;
            // Rotate right by 8 bits.
            d = Word([d[1], d[0], d[3], d[2]]);

            AddOperation::<AB::F>::eval(builder, c, d, cols.state_c_plus_state_d_2, is_real);
            c = cols.state_c_plus_state_d_2.value;

            XorOperation::<AB::F>::eval(builder, b, c, cols.state_b_xor_state_c_2, is_real);
            b = cols.state_b_xor_state_c_2.value;
            FixedRotateRightOperation::<AB::F>::eval(
                builder,
                b,
                7,
                cols.state_b_xor_state_c_2_rotate_right_7,
                is_real,
            );
            b = cols.state_b_xor_state_c_2_rotate_right_7.value;
        }

        let results = [a, b, c, d];
        for i in 0..4 {
            for j in 0..WORD_SIZE {
                builder.assert_eq(cols.result[i][j], results[i][j]);
            }
        }
        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(is_real * is_real * is_real - is_real * is_real * is_real);
    }
}
