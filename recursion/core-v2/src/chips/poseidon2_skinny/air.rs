//! The air module contains the AIR constraints for the poseidon2 chip.  
//! At the moment, we're only including memory constraints to test the new memory argument.

use std::array;
use std::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::AbstractField;
use p3_matrix::Matrix;

use crate::builder::SP1RecursionAirBuilder;

use super::columns::preprocessed::Poseidon2PreprocessedCols;
use super::columns::{Poseidon2, NUM_POSEIDON2_DEGREE3_COLS, NUM_POSEIDON2_DEGREE9_COLS};
use super::{external_linear_layer, Poseidon2SkinnyChip, WIDTH};

impl<F, const DEGREE: usize> BaseAir<F> for Poseidon2SkinnyChip<DEGREE> {
    fn width(&self) -> usize {
        if DEGREE == 3 || DEGREE == 5 {
            NUM_POSEIDON2_DEGREE3_COLS
        } else if DEGREE == 9 || DEGREE == 17 {
            NUM_POSEIDON2_DEGREE9_COLS
        } else {
            panic!("Unsupported degree: {}", DEGREE);
        }
    }
}

impl<AB, const DEGREE: usize> Air<AB> for Poseidon2SkinnyChip<DEGREE>
where
    AB: SP1RecursionAirBuilder + PairBuilder,
    AB::Var: 'static,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = Self::convert::<AB::Var>(main.row_slice(0));
        let next_row = Self::convert::<AB::Var>(main.row_slice(1));
        let prepr = builder.preprocessed();
        let prep_local = prepr.row_slice(0);
        let prep_local: &Poseidon2PreprocessedCols<_> = (*prep_local).borrow();

        // Dummy constraints to normalize to DEGREE.
        let lhs = (0..DEGREE)
            .map(|_| local_row.state_var()[0].into())
            .product::<AB::Expr>();
        let rhs = (0..DEGREE)
            .map(|_| local_row.state_var()[0].into())
            .product::<AB::Expr>();
        builder.assert_eq(lhs, rhs);

        // For now, include only memory constraints.
        (0..WIDTH).for_each(|i| {
            builder.receive_single(
                prep_local.memory_preprocessed[i].addr,
                local_row.state_var()[i],
                prep_local.memory_preprocessed[i].read_mult,
            )
        });

        (0..WIDTH).for_each(|i| {
            builder.send_single(
                prep_local.memory_preprocessed[i].addr,
                local_row.state_var()[i],
                prep_local.memory_preprocessed[i].write_mult,
            )
        });

        self.eval_input_round(
            builder,
            local_row.as_ref(),
            next_row.as_ref(),
            prep_local.round_counters_preprocessed.is_input_round,
        );

        self.eval_external_round(
            builder,
            local_row.as_ref(),
            next_row.as_ref(),
            prep_local.round_counters_preprocessed.round_constants,
            prep_local.round_counters_preprocessed.is_external_round,
        );
    }
}

impl<const DEGREE: usize> Poseidon2SkinnyChip<DEGREE> {
    fn eval_input_round<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local_row: &dyn Poseidon2<AB::Var>,
        next_row: &dyn Poseidon2<AB::Var>,
        is_input_row: AB::Var,
    ) where
        AB::Var: 'static,
    {
        let mut local_state: [AB::Expr; WIDTH] =
            array::from_fn(|i| local_row.state_var()[i].into());

        external_linear_layer(&mut local_state);

        let next_state = next_row.state_var();
        for i in 0..WIDTH {
            builder
                .when(is_input_row)
                .assert_eq(next_state[i], local_state[i].clone());
        }
    }

    fn eval_external_round<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local_row: &dyn Poseidon2<AB::Var>,
        next_row: &dyn Poseidon2<AB::Var>,
        round_constants: [AB::Var; WIDTH],
        is_external_row: AB::Var,
    ) where
        AB::Var: 'static,
    {
        let local_state = local_row.state_var();

        // Add the round constants.
        let add_rc: [AB::Expr; WIDTH] =
            core::array::from_fn(|i| local_state[i].into() + round_constants[i]);

        // Apply the sboxes.
        // See `populate_external_round` for why we don't have columns for the sbox output here.
        let mut sbox_deg_7: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
        let mut sbox_deg_3: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
        for i in 0..WIDTH {
            let calculated_sbox_deg_3 = add_rc[i].clone() * add_rc[i].clone() * add_rc[i].clone();

            if let Some(external_sbox) = local_row.s_box_state() {
                builder
                    .when(is_external_row)
                    .assert_eq(external_sbox[i].into(), calculated_sbox_deg_3);
                sbox_deg_3[i] = external_sbox[i].into();
            } else {
                sbox_deg_3[i] = calculated_sbox_deg_3;
            }

            sbox_deg_7[i] = sbox_deg_3[i].clone() * sbox_deg_3[i].clone() * add_rc[i].clone();
        }

        // Apply the linear layer.
        let mut state = sbox_deg_7;
        external_linear_layer(&mut state);

        let next_state = next_row.state_var();
        for i in 0..WIDTH {
            builder
                .when_transition()
                .when(is_external_row)
                .assert_eq(next_state[i], state[i].clone());
        }
    }

    // fn eval_internal_rounds<AB: SP1RecursionAirBuilder>(
    //     &self,
    //     builder: &mut AB,
    //     perm_cols: &dyn Permutation<AB::Var>,
    // ) {
    //     let state = &perm_cols.internal_rounds_state();
    //     let s0 = perm_cols.internal_rounds_s0();
    //     let mut state: [AB::Expr; WIDTH] = core::array::from_fn(|i| state[i].into());
    //     for r in 0..NUM_INTERNAL_ROUNDS {
    //         // Add the round constant.
    //         let round = r + NUM_EXTERNAL_ROUNDS / 2;
    //         let add_rc = if r == 0 {
    //             state[0].clone()
    //         } else {
    //             s0[r - 1].into()
    //         } + AB::Expr::from_wrapped_u32(RC_16_30_U32[round][0]);

    //         let mut sbox_deg_3 = add_rc.clone() * add_rc.clone() * add_rc.clone();
    //         if let Some(internal_sbox) = perm_cols.internal_rounds_sbox() {
    //             builder.assert_eq(internal_sbox[r], sbox_deg_3);
    //             sbox_deg_3 = internal_sbox[r].into();
    //         }

    //         // See `populate_internal_rounds` for why we don't have columns for the sbox output here.
    //         let sbox_deg_7 = sbox_deg_3.clone() * sbox_deg_3.clone() * add_rc.clone();

    //         // Apply the linear layer.
    //         // See `populate_internal_rounds` for why we don't have columns for the new state here.
    //         state[0] = sbox_deg_7.clone();
    //         internal_linear_layer(&mut state);

    //         if r < NUM_INTERNAL_ROUNDS - 1 {
    //             builder.assert_eq(s0[r], state[0].clone());
    //         }
    //     }

    //     let external_state = perm_cols.external_rounds_state()[NUM_EXTERNAL_ROUNDS / 2];
    //     for i in 0..WIDTH {
    //         builder.assert_eq(external_state[i], state[i].clone())
    //     }
    // }
}
