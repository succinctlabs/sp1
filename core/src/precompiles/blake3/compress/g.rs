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
use crate::operations::AddOperation;
use crate::operations::FixedRotateRightOperation;
use crate::operations::XorOperation;
use crate::runtime::Segment;
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
    // Rotate right by 12 bits by just shifting bytes.
    pub state_a_plus_state_b_2: AddOperation<T>,
    pub state_a_plus_state_b_2_add_y: AddOperation<T>,
    // Rotate right by 8 bits by just shifting bytes.
    pub state_d_xor_state_a_2: XorOperation<T>,
    pub state_c_plus_state_d_2: AddOperation<T>,
    pub state_b_xor_state_c_2: XorOperation<T>,
    pub state_b_xor_state_c_2_rotate_right_7: FixedRotateRightOperation<T>,
    /// `state[a]`, `state[b]`, `state[c]`, `state[d]` after all the steps.
    pub result: [T; 4],
}

impl<F: Field> GOperation<F> {
    pub fn populate(&mut self, input: [u32; 6]) -> [u32; 4] {
        let a = input[0];
        let b = input[1];
        let c = input[2];
        let d = input[3];
        // TODO: Fill in the logic!

        [a, b, c, d]
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: AddOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        // TODO: Fill in the logic!
        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(a[0] * b[0] * cols.value[0] - a[0] * b[0] * cols.value[0]);
    }
}
