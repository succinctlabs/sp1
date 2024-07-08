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
    columns::{Poseidon2, NUM_POSEIDON2_DEGREE3_COLS, NUM_POSEIDON2_DEGREE9_COLS},
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
    fn eval(&self, builder: &mut AB) {}
}

impl<const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn eval_poseidon2<AB>(&self, _builder: &mut AB, _local_row: &dyn Poseidon2<AB::Var>)
    where
        AB: SP1RecursionAirBuilder,
        AB::Var: 'static,
    {
        // Check that all the memory access columns are correct.
        // self.eval_mem(...);

        // Check that the permutation columns are correct.
        // self.eval_perm(...);
    }
}
