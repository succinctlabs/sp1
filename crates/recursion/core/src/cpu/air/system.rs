use p3_air::AirBuilder;
use p3_field::Field;
use sp1_stark::air::BaseAirBuilder;

use crate::{
    air::{RecursionPublicValues, SP1RecursionAirBuilder},
    cpu::{CpuChip, CpuCols},
};

impl<F: Field, const L: usize> CpuChip<F, L> {
    /// Eval the system instructions (TRAP, HALT).
    pub fn eval_system_instructions<AB>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        public_values: &RecursionPublicValues<AB::Expr>,
    ) where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        let is_system_instruction = self.is_system_instruction::<AB>(local);

        // Verify that the last real row is either TRAP or HALT.
        builder
            .when_transition()
            .when(local.is_real)
            .when_not(next.is_real)
            .assert_one(is_system_instruction.clone());

        builder.when_last_row().when(local.is_real).assert_one(is_system_instruction.clone());

        // Verify that all other real rows are not TRAP or HALT.
        builder
            .when_transition()
            .when(local.is_real)
            .when(next.is_real)
            .assert_zero(is_system_instruction);

        // Verify the correct public value exit code.
        builder.when(local.selectors.is_trap).assert_one(public_values.exit_code.clone());

        builder.when(local.selectors.is_halt).assert_zero(public_values.exit_code.clone());
    }
}
