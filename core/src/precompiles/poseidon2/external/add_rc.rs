//! The `add_rc` operation for the Poseidon2 permutation.
//!
//! Ideally, this would be under `src/operations`, but this uses constants specific to Poseidon2,
//! and they are not visible from there. Instead of adding more dependencies to `operations`, this
//! is placed here, at least for now.
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_air::AirBuilder;
// use p3_air::AirBuilder;
use p3_field::AbstractField;
use p3_field::Field;

use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::Array;
use crate::air::CurtaAirBuilder;
use crate::air::Word;

use crate::air::WORD_SIZE;
use crate::operations::AddOperation;
use crate::precompiles::poseidon2::NUM_WORDS_POSEIDON2_STATE;
use crate::runtime::Segment;

use super::columns::POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS;
use super::columns::POSEIDON2_ROUND_CONSTANTS;
// use p3_field::AbstractField;

/// A set of columns needed to compute the `add_rc` of the input state.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AddRcOperation<T> {
    /// An array whose i-th element is the result of adding the appropriate round constant to the
    /// i-th word of the input state.
    pub add_operation: Array<AddOperation<T>, NUM_WORDS_POSEIDON2_STATE>,
}

impl<F: Field> AddRcOperation<F> {
    // TODO: Do I need segment?
    pub fn populate(
        &mut self,
        segment: &mut Segment,
        array: &[u32; NUM_WORDS_POSEIDON2_STATE],
        round: usize,
    ) -> [u32; NUM_WORDS_POSEIDON2_STATE] {
        // 1. Actually compute add_rc of the input through FieldOps operations.
        // 2. Return the result.
        let mut results = [0; NUM_WORDS_POSEIDON2_STATE];

        for word_index in 0..NUM_WORDS_POSEIDON2_STATE {
            let res = self.add_operation[word_index].populate(
                segment,
                array[word_index],
                POSEIDON2_ROUND_CONSTANTS[round][word_index],
            );
            results[word_index] = res;
        }
        results
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        input_state: Array<Word<AB::Var>, NUM_WORDS_POSEIDON2_STATE>,
        is_round_n: Array<AB::Var, POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS>,
        round_constant: Array<Word<AB::Var>, NUM_WORDS_POSEIDON2_STATE>,
        cols: AddRcOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        // Iterate through each limb.
        for word_index in 0..NUM_WORDS_POSEIDON2_STATE {
            // Calculate the round constant for this limb.
            let round_constant = {
                let mut acc: Vec<AB::Expr> = vec![AB::F::zero().into(); WORD_SIZE];

                // The round constant is is_round_n[round] * round_constant[round], but we need to
                // do this multiplication per limb.
                for round in 0..POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS {
                    let rc: Word<AB::F> = Word::from(POSEIDON2_ROUND_CONSTANTS[round][word_index]);
                    for limb in 0..WORD_SIZE {
                        acc[limb] += is_round_n[round] * rc[limb];
                    }
                }

                for limb in 0..WORD_SIZE {
                    builder
                        .when(is_real)
                        .assert_eq(acc[limb].clone(), round_constant[word_index][limb]);
                }
                round_constant[word_index]
            };

            AddOperation::<AB::F>::eval(
                builder,
                input_state[word_index],
                round_constant,
                cols.add_operation[word_index],
                is_real,
            );
        }

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(is_real * is_real * is_real - is_real * is_real * is_real);
    }
}
