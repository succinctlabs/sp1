use p3_air::AirBuilder;
use p3_field::Field;
use sp1_core::air::BaseAirBuilder;

use crate::{
    air::SP1RecursionAirBuilder,
    cpu::{CpuChip, CpuCols},
};

impl<F: Field> CpuChip<F> {
    /// Eval the system instructions (TRAP, HALT).
    ///
    /// This method will contrain the following:
    /// 1) Ensure that none of the instructions are TRAP.
    /// 2) Ensure that the last real instruction is a HALT.
    pub fn eval_system_instructions<AB>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) where
        AB: SP1RecursionAirBuilder,
    {
        builder
            .when(local.is_real)
            .assert_zero(local.selectors.is_trap);

        builder
            .when_transition()
            .when(local.is_real)
            .when_not(next.is_real)
            .assert_one(local.selectors.is_halt);
    }
}
