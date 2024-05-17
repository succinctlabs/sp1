use p3_air::AirBuilder;
use p3_field::Field;
use sp1_core::air::BaseAirBuilder;

use crate::{
    air::{RecursionPublicValues, SP1RecursionAirBuilder},
    cpu::{CpuChip, CpuCols},
};

impl<F: Field> CpuChip<F> {
    /// Eval the system instructions (TRAP, HALT).
    pub fn eval_system_instructions<AB>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        public_values: &RecursionPublicValues<AB::Expr>,
    ) where
        AB: SP1RecursionAirBuilder,
    {
        // Verify that the last real row is either TRAP or HALT.
        // We also verify below that the last row is not real.
        builder
            .when_transition()
            .when(local.is_real)
            .when_not(next.is_real)
            .assert_one(local.selectors.is_trap + local.selectors.is_halt);

        builder
            .when_last_row()
            .when(local.is_real)
            .assert_one(local.selectors.is_trap + local.selectors.is_halt);

        // Verify that all other real rows are not TRAP or HALT.
        builder
            .when_transition()
            .when(local.is_real)
            .when(next.is_real)
            .assert_zero(local.selectors.is_trap + local.selectors.is_halt);

        // Verify the correct public value exit code.
        builder
            .when(local.selectors.is_trap)
            .assert_one(public_values.exit_code.clone());

        builder
            .when(local.selectors.is_halt)
            .assert_zero(public_values.exit_code.clone());
    }
}
