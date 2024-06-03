use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};

use crate::{
    air::SP1RecursionAirBuilder,
    cpu::{CpuChip, CpuCols},
    memory::MemoryCols,
    runtime::STACK_SIZE,
};

impl<F: Field, const L: usize> CpuChip<F, L> {
    /// Eval the JUMP instructions.
    ///
    /// This method will verify the fp column values and add to the `next_pc` expression.
    pub fn eval_jump<AB>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        next_pc: &mut AB::Expr,
    ) where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        // Verify the next row's fp.
        builder
            .when_first_row()
            .assert_eq(local.fp, F::from_canonical_usize(STACK_SIZE));
        let not_jump_instruction = AB::Expr::one() - self.is_jump_instruction::<AB>(local);
        let expected_next_fp = local.selectors.is_jal * (local.fp + local.c.value()[0])
            + local.selectors.is_jalr * local.a.value()[0]
            + not_jump_instruction * local.fp;
        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(next.fp, expected_next_fp);

        // Add to the `next_pc` expression.
        *next_pc += local.selectors.is_jal * (local.pc + local.b.value()[0]);
        *next_pc += local.selectors.is_jalr * local.b.value()[0];
    }
}
