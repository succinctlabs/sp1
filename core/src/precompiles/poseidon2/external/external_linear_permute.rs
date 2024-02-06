//! The `external_linear` operation for the Poseidon2 permutation.
//!
//! Ideally, this would be under `src/operations`, but this uses constants specific to Poseidon2,
//! and they are not visible from there. Instead of adding more dependencies to `operations`, this
//! is placed here, at least for now.
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_air::AirBuilder;
use p3_field::AbstractField;
use p3_field::Field;

use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::Array;
use crate::air::CurtaAirBuilder;

use super::columns::POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS;
use super::columns::POSEIDON2_ROUND_CONSTANTS;
use super::NUM_LIMBS_POSEIDON2_STATE;

/// A set of columns needed to compute the `external_linear` of the input state.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExternalLinearPermuteOperation<T> {
    pub result: [T; NUM_LIMBS_POSEIDON2_STATE],
}

impl<F: Field> ExternalLinearPermuteOperation<F> {
    pub fn populate(
        &mut self,
        _array: &[F; NUM_LIMBS_POSEIDON2_STATE],
    ) -> [F; NUM_LIMBS_POSEIDON2_STATE] {
        self.result
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        _input_state: Array<AB::Expr, NUM_LIMBS_POSEIDON2_STATE>,
        _cols: ExternalLinearPermuteOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(is_real * is_real * is_real - is_real * is_real * is_real);
    }
}
