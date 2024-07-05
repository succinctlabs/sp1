//! The air module contains the AIR constraints for the poseidon2 chip.  Those constraints will
//! enforce the following properties:
//!
use std::borrow::Borrow;

use p3_air::{Air, BaseAir, PairBuilder};
use p3_matrix::Matrix;

use sp1_recursion_core::air::SP1RecursionAirBuilder;

// pub mod control_flow;
pub mod memory;
pub mod permutation;
// pub mod state_transition;
// pub mod syscall_params;

use super::{
    columns::{
        memory::MemoryPreprocessed, Poseidon2, NUM_POSEIDON2_DEGREE3_COLS,
        NUM_POSEIDON2_DEGREE9_COLS,
    },
    Poseidon2WideChip,
};

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
        let local_row = Self::convert::<AB::Var>(main.row_slice(0));

        let prep = builder.preprocessed();
        let prep = prep.row_slice(0);
        // let local_prep: &MemoryPreprocessed<AB::Var> = (*prep).borrow();
        // let next_row = Self::convert::<AB::Var>(main.row_slice(1));

        // Dummy constraints to normalize to DEGREE.
        let lhs = (0..DEGREE)
            .map(|_| local_row.memory().input[0].into())
            .product::<AB::Expr>();
        let rhs = (0..DEGREE)
            .map(|_| local_row.memory().input[0].into())
            .product::<AB::Expr>();
        builder.assert_eq(lhs, rhs);

        self.eval_poseidon2(builder, local_row.as_ref(), (*prep).borrow());
    }
}

impl<const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn eval_poseidon2<AB>(
        &self,
        builder: &mut AB,
        local_row: &dyn Poseidon2<AB::Var>,
        prep: &MemoryPreprocessed<AB::Var>,
    ) where
        AB: SP1RecursionAirBuilder,
        AB::Var: 'static,
    {
        let local_memory = local_row.memory();
        let local_memory_prepr = prep;
        let local_perm = local_row.permutation();

        // Check that all the memory access columns are correct.
        self.eval_mem(
            builder,
            local_memory,
            local_memory_prepr,
            std::array::from_fn(|i| local_memory_prepr.output_mult[i].into()),
        );

        // Check that the permutation columns are correct.
        self.eval_perm(builder, local_perm.as_ref(), local_memory);
    }
}
