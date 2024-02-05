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

use crate::air::Array;
use crate::air::CurtaAirBuilder;

use super::columns::POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS;
use super::columns::POSEIDON2_ROUND_CONSTANTS;
use super::NUM_LIMBS_POSEIDON2_STATE;

/// A set of columns needed to compute the `add_rc` of the input state.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AddRcOperation<T> {
    /// An array whose i-th element is the result of adding the appropriate round constant to the
    /// i-th element of the input state.
    pub result: [T; NUM_LIMBS_POSEIDON2_STATE],
}

impl<F: Field> AddRcOperation<F> {
    // TODO: Do I need segment?
    pub fn populate(
        &mut self,
        array: &[F; NUM_LIMBS_POSEIDON2_STATE],
        round: usize,
    ) -> [F; NUM_LIMBS_POSEIDON2_STATE] {
        // 1. Add the appropriate round constant to each limb of the input state.
        // 2. Return the result.
        for word_index in 0..NUM_LIMBS_POSEIDON2_STATE {
            self.result[word_index] = array[word_index]
                + F::from_canonical_u32(POSEIDON2_ROUND_CONSTANTS[round][word_index]);
        }
        self.result
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        input_state: Array<AB::Expr, NUM_LIMBS_POSEIDON2_STATE>,
        is_round_n: Array<AB::Var, POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS>,
        round_constant: Array<AB::Var, NUM_LIMBS_POSEIDON2_STATE>,
        cols: AddRcOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        // Iterate through each limb.
        for limb_index in 0..NUM_LIMBS_POSEIDON2_STATE {
            // Calculate the round constant for this limb.
            let round_constant = {
                let mut acc: AB::Expr = AB::F::zero().into();

                // The round constant is the sum of is_round_n[round] * round_constant[round].
                for round in 0..POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS {
                    let rc: AB::Expr =
                        AB::F::from_canonical_u32(POSEIDON2_ROUND_CONSTANTS[round][limb_index])
                            .into();
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
