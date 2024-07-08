//! The air module contains the AIR constraints for the poseidon2 chip.  Those constraints will
//! enforce the following properties:
//!

use std::borrow::Borrow;

use p3_air::{Air, BaseAir, PairBuilder};
use p3_matrix::Matrix;

use crate::builder::SP1RecursionAirBuilder;

use crate::poseidon2_wide::{
    columns::{NUM_POSEIDON2_DEGREE3_COLS, NUM_POSEIDON2_DEGREE9_COLS},
    Poseidon2WideChip,
};

use super::columns::preprocessed::Poseidon2PreprocessedCols;
use super::WIDTH;

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
            .map(|_| local_row.state_var()[0].into())
            .product::<AB::Expr>();
        let rhs = (0..DEGREE)
            .map(|_| local_row.state_var()[0].into())
            .product::<AB::Expr>();
        builder.assert_eq(lhs, rhs);

        // For now, include only memory constraints.
        (0..WIDTH).for_each(|i| {
            builder.receive_single(
                prep_local.memory_preprocessed.memory_prepr[i].addr,
                local_row.state_var()[i],
                prep_local.memory_preprocessed.memory_prepr[i].read_mult,
            )
        });

        // For now, include only memory constraints.
        (0..WIDTH).for_each(|i| {
            builder.send_single(
                prep_local.memory_preprocessed.memory_prepr[i].addr,
                local_row.state_var()[i],
                prep_local.memory_preprocessed.memory_prepr[i].write_mult,
            )
        });

        // builder.receive_single(prep_local.addrs.in2, *in2, prep_local.is_real);

        // builder.send_single(prep_local.addrs.out, *out, prep_local.mult);
    }
}
