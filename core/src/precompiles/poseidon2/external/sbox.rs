//! The `sbox` operation for the Poseidon2 permutation.
//!
//! Ideally, this would be under `src/operations`, but this uses constants specific to Poseidon2,
//! and they are not visible from there. Instead of adding more dependencies to `operations`, this
//! is placed here, at least for now.
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::AbstractField;
use p3_field::Field;

use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;

use super::columns::P2_SBOX_EXPONENT;
use super::columns::P2_SBOX_EXPONENT_LOG2;
use super::P2_WIDTH;

/// A set of columns needed to compute the `sbox` of the input state.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SBoxOperation<T> {
    /// A 2-dimensional array whose `(i, j)`-th element is `pow(input[i], 2^j)`. This is used to
    /// calculate the result of the `sbox` operation with the exponentiation by squaring algorithm.
    pub powers: [[T; P2_SBOX_EXPONENT_LOG2]; P2_WIDTH],

    /// A 2-dimensional array whose `(i, j)`th element is the accumulate variable for the `j`th
    /// iteration in the exponentiation by squaring algorithm for the `i`th element of the input
    /// state. The final results of the `sbox` operation is stored in `acc[i].last()` for each `i`.
    ///
    /// This helps avoid degree explosion.
    pub acc: [[T; P2_SBOX_EXPONENT_LOG2]; P2_WIDTH],
}

impl<F: Field> SBoxOperation<F> {
    pub fn populate(&mut self, array: &[F; P2_WIDTH]) -> [F; P2_WIDTH] {
        for limb_index in 0..P2_WIDTH {
            // Continue squaring the limb_index-th input state.
            self.powers[limb_index][0] = array[limb_index];
            for i in 1..P2_SBOX_EXPONENT_LOG2 {
                self.powers[limb_index][i] =
                    self.powers[limb_index][i - 1] * self.powers[limb_index][i - 1];
            }

            // Exponentiation by squaring algorithm.
            let mut acc = F::one();
            for bit in 0..P2_SBOX_EXPONENT_LOG2 {
                if (P2_SBOX_EXPONENT >> bit) & 1 == 1 {
                    acc *= self.powers[limb_index][bit];
                }
                self.acc[limb_index][bit] = acc;
            }
        }

        self.acc.map(|x| *x.last().unwrap())
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        input_state: [AB::Var; P2_WIDTH],
        cols: SBoxOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        builder.assert_bool(is_real);
        for limb_index in 0..P2_WIDTH {
            // Continue squaring the limb_index-th input state.
            {
                builder.assert_eq(cols.powers[limb_index][0], input_state[limb_index]);
                for i in 1..P2_SBOX_EXPONENT_LOG2 {
                    builder.assert_eq(
                        cols.powers[limb_index][i],
                        cols.powers[limb_index][i - 1] * cols.powers[limb_index][i - 1],
                    );
                }
            }

            // Exponentiation by squaring algorithm.
            {
                for bit in 0..P2_SBOX_EXPONENT_LOG2 {
                    let acc: AB::Expr = if bit == 0 {
                        AB::Expr::one()
                    } else {
                        cols.acc[limb_index][bit - 1].into()
                    };

                    if (P2_SBOX_EXPONENT >> bit) & 1 == 1 {
                        builder.assert_eq(
                            cols.acc[limb_index][bit],
                            acc * cols.powers[limb_index][bit],
                        );
                    } else {
                        builder.assert_eq(cols.acc[limb_index][bit], acc);
                    }
                }
            }
        }

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(is_real * is_real * is_real - is_real * is_real * is_real);
    }
}
