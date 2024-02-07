//! The `add_rc` operation for the Poseidon2 permutation.
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

use crate::air::CurtaAirBuilder;

use super::P2_EXTERNAL_ROUND_COUNT;
use super::P2_ROUND_CONSTANTS;
use super::P2_WIDTH;

/// A set of columns needed to compute the `add_rc` of the input state.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AddRcOperation<T> {
    pub result: [T; P2_WIDTH],
}

impl<F: Field> AddRcOperation<F> {
    pub fn populate(&mut self, array: &[F; P2_WIDTH], round: usize) -> [F; P2_WIDTH] {
        // 1. Add the appropriate round constant to each limb of the input state.
        // 2. Return the result.
        for word_index in 0..P2_WIDTH {
            self.result[word_index] =
                array[word_index] + F::from_canonical_u32(P2_ROUND_CONSTANTS[round][word_index]);
        }
        self.result
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        input_state: [AB::Expr; P2_WIDTH],
        is_round_n: [AB::Var; P2_EXTERNAL_ROUND_COUNT],
        round_constant: [AB::Var; P2_WIDTH],
        cols: AddRcOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        // Iterate through each limb.
        for limb_index in 0..P2_WIDTH {
            // Calculate the round constant for this limb.
            let round_constant = {
                let mut acc: AB::Expr = AB::F::zero().into();

                // The round constant is the sum of is_round_n[round] * round_constant[round].
                for round in 0..P2_EXTERNAL_ROUND_COUNT {
                    let rc: AB::Expr =
                        AB::F::from_canonical_u32(P2_ROUND_CONSTANTS[round][limb_index]).into();
                    acc += is_round_n[round] * rc;
                }

                builder
                    .when(is_real)
                    .assert_eq(acc.clone(), round_constant[limb_index]);

                round_constant[limb_index]
            };

            // Input + RC = Result.
            builder.assert_eq(
                input_state[limb_index].clone() + round_constant,
                cols.result[limb_index],
            );
        }

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(is_real * is_real * is_real - is_real * is_real * is_real);
    }
}
