use core::borrow::Borrow;
use core::borrow::BorrowMut;
use num::integer::Roots;
use p3_air::AirBuilder;
use p3_field::AbstractField;
use p3_field::Field;

use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::operations::AddOperation;
use crate::operations::FixedRotateRightOperation;
use crate::operations::XorOperation;
/// A set of columns needed to compute the `add_rc` of the input state.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MixOperation<T> {
    pub state_a_plus_state_b: AddOperation<T>,
    pub state_d_xor_state_a: XorOperation<T>,
    // Rotate right 16 can be done by just shifting bytes, so there's no operation necessary.
    pub state_c_plus_state_d: AddOperation<T>,
    pub state_b_xor_state_c: XorOperation<T>,

    /// state[a], state[b], state[c], state[d] after the first 4 ops.
    pub intermediate_states: [T; 4],

    // Rotate right 12 can be done by just shifting bytes, so there's no operation necessary.
    pub state_a_plus_state_b_2: AddOperation<T>,
    pub state_a_plus_state_b_2_add_y: AddOperation<T>,

    pub state_d_xor_state_a_2: XorOperation<T>,

    pub state_c_plus_state_d_2: AddOperation<T>,

    pub state_b_xor_state_c_2: XorOperation<T>,
    pub state_b_xor_state_c_2_rotate_right_7: FixedRotateRightOperation<T>,

    /// state[a], state[b], state[c], state[d] after all the steps.
    pub result: [T; 4],
}
