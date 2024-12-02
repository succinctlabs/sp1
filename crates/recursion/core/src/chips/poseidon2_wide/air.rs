use std::borrow::Borrow;

use p3_air::{Air, BaseAir, PairBuilder};
use p3_matrix::Matrix;
use sp1_core_machine::operations::poseidon2::air::eval_external_round;
use sp1_core_machine::operations::poseidon2::air::eval_internal_rounds;

use sp1_core_machine::operations::poseidon2::permutation::NUM_POSEIDON2_DEGREE3_COLS;
use sp1_core_machine::operations::poseidon2::permutation::NUM_POSEIDON2_DEGREE9_COLS;
use sp1_core_machine::operations::poseidon2::NUM_EXTERNAL_ROUNDS;
use sp1_core_machine::operations::poseidon2::WIDTH;

use super::Poseidon2WideChip;
use crate::builder::SP1RecursionAirBuilder;
use crate::chips::poseidon2_wide::columns::preprocessed::Poseidon2PreprocessedColsWide;

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
        let prep_local: &Poseidon2PreprocessedColsWide<_> = (*prep_local).borrow();

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
            builder.send_single(
                prep_local.input[i],
                local_row.external_rounds_state()[0][i],
                prep_local.is_real_neg,
            )
        });

        (0..WIDTH).for_each(|i| {
            builder.send_single(
                prep_local.output[i].addr,
                local_row.perm_output()[i],
                prep_local.output[i].mult,
            )
        });

        // Apply the external rounds.
        for r in 0..NUM_EXTERNAL_ROUNDS {
            eval_external_round(builder, local_row.as_ref(), r);
        }

        // Apply the internal rounds.
        eval_internal_rounds(builder, local_row.as_ref());
    }
}
