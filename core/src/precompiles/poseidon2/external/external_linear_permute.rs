//! The `external_linear` operation for the Poseidon2 permutation.
//!
//! Ideally, this would be under `src/operations`, but this uses constants specific to Poseidon2,
//! and they are not visible from there. Instead of adding more dependencies to `operations`, this
//! is placed here, at least for now.
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;

use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;

use super::external_linear_permute_mut;
use super::P2_WIDTH;

/// A set of columns needed to compute the `external_linear` of the input state.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExternalLinearPermuteOperation<T> {
    pub result: [T; P2_WIDTH],
}

impl<F: Field> ExternalLinearPermuteOperation<F> {
    pub fn populate(&mut self, array: &[F; P2_WIDTH]) -> [F; P2_WIDTH] {
        self.result = *array;
        external_linear_permute_mut(&mut self.result);
        self.result
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        input_state: [AB::Var; P2_WIDTH],
        cols: ExternalLinearPermuteOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        let result = {
            let mut input: [AB::Expr; P2_WIDTH] = input_state.map(|x| x.into());
            external_linear_permute_mut::<AB::Expr, P2_WIDTH>(&mut input);
            input
        };

        for i in 0..P2_WIDTH {
            builder.assert_eq(result[i].clone(), cols.result[i]);
        }

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(is_real * is_real * is_real - is_real * is_real * is_real);
    }
}
