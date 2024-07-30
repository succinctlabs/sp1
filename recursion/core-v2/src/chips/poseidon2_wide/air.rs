//! The air module contains the AIR constraints for the poseidon2 chip.  
//! At the moment, we're only including memory constraints to test the new memory argument.

use std::array;
use std::borrow::Borrow;

use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_primitives::RC_16_30_U32;
use sp1_recursion_core::poseidon2_wide::NUM_EXTERNAL_ROUNDS;

use crate::builder::SP1RecursionAirBuilder;

use super::columns::permutation::Poseidon2;
use super::columns::preprocessed::Poseidon2PreprocessedCols;
use super::columns::{NUM_POSEIDON2_DEGREE3_COLS, NUM_POSEIDON2_DEGREE9_COLS};
use super::{external_linear_layer, Poseidon2WideChip, WIDTH};

impl<F, const DEGREE: usize> BaseAir<F> for Poseidon2WideChip<DEGREE> {
    fn width(&self) -> usize {
        if DEGREE == 3 {
            NUM_POSEIDON2_DEGREE3_COLS
        } else if DEGREE == 9 || DEGREE == 17 {
            NUM_POSEIDON2_DEGREE9_COLS
        } else {
            panic!("Unsupported degree: {}", DEGREE);
        }
    }
}

impl<AB, const DEGREE: usize> Air<AB> for Poseidon2WideChip<DEGREE>
where
    AB: SP1RecursionAirBuilder + PairBuilder,
    AB::Var: 'static,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let prepr = builder.preprocessed();
        let local_row = Self::convert::<AB::Var>(main.row_slice(0));
        let prep_local = prepr.row_slice(0);
        let prep_local: &Poseidon2PreprocessedCols<_> = (*prep_local).borrow();

        // Dummy constraints to normalize to DEGREE.
        let lhs = (0..DEGREE)
            .map(|_| local_row.external_rounds_state()[0][0].into())
            .product::<AB::Expr>();
        let rhs = (0..DEGREE)
            .map(|_| local_row.external_rounds_state()[0][0].into())
            .product::<AB::Expr>();
        builder.assert_eq(lhs, rhs);

        // For now, include only memory constraints.
        (0..WIDTH).for_each(|i| {
            builder.receive_single(
                prep_local.memory_preprocessed[i].addr,
                local_row.external_rounds_state()[0][i],
                prep_local.memory_preprocessed[i].read_mult,
            )
        });

        (0..WIDTH).for_each(|i| {
            builder.send_single(
                prep_local.memory_preprocessed[i + WIDTH].addr,
                local_row.perm_output()[i],
                prep_local.memory_preprocessed[i + WIDTH].write_mult,
            )
        });

        // Apply the first half of the external rounds.
        for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
            self.eval_external_round(builder, local_row.as_ref(), r);
        }
    }
}

impl<const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    fn eval_external_round<AB>(
        &self,
        builder: &mut AB,
        local_row: &dyn Poseidon2<AB::Var>,
        r: usize,
    ) where
        AB: SP1RecursionAirBuilder + PairBuilder,
    {
        let mut local_state: [AB::Expr; WIDTH] =
            array::from_fn(|i| local_row.external_rounds_state()[r][i].into());

        // For the first round, apply the linear layer.
        if r == 0 {
            external_linear_layer(&mut local_state);
        }

        // Add the round constants.
        let add_rc: [AB::Expr; WIDTH] = array::from_fn(|i| {
            local_state[i].clone() + AB::Expr::from_canonical_u32(RC_16_30_U32[r][i])
        });

        // Apply the sboxes.
        // See `populate_external_round` for why we don't have columns for the sbox output here.
        let mut sbox_deg_7: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
        let mut sbox_deg_3: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
        for i in 0..WIDTH {
            let calculated_sbox_deg_3 = add_rc[i].clone() * add_rc[i].clone() * add_rc[i].clone();

            if let Some(external_sbox) = local_row.external_rounds_sbox() {
                builder.assert_eq(external_sbox[r][i].into(), calculated_sbox_deg_3);
                sbox_deg_3[i] = external_sbox[r][i].into();
            } else {
                sbox_deg_3[i] = calculated_sbox_deg_3;
            }

            sbox_deg_7[i] = sbox_deg_3[i].clone() * sbox_deg_3[i].clone() * add_rc[i].clone();
        }

        // Apply the linear layer.
        let mut state = sbox_deg_7;
        external_linear_layer(&mut state);

        let next_state = if r == NUM_EXTERNAL_ROUNDS / 2 {
            local_row.internal_rounds_state()
        } else if r == NUM_EXTERNAL_ROUNDS - 1 {
            local_row.perm_output()
        } else {
            &local_row.external_rounds_state()[r + 1]
        };

        for i in 0..WIDTH {
            builder.assert_eq(next_state[i], state[i].clone());
        }
    }
}
