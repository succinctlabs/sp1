use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};

use crate::{
    air::SP1RecursionAirBuilder,
    cpu::{CpuChip, CpuCols},
    memory::MemoryCols,
};

impl<F: Field> CpuChip<F> {
    /// Eval the JUMP instructions.
    pub fn eval_jump<AB>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        next_pc: &mut AB::Expr,
    ) where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        // Contribute to the `next_pc`` expression.
        *next_pc += local.selectors.is_jal * (local.pc + local.b.value()[0]);
        *next_pc += local.selectors.is_jalr * local.b.value()[0];

        let one: AB::Expr = AB::Expr::one();
        let is_jump_instruction = self.is_jump_instruction::<AB>(local);

        // Verify the next row's fp.
        builder
            .when_transition()
            .when(local.selectors.is_jal)
            .when(next.is_real)
            .assert_eq(next.fp, local.fp + local.c.value()[0]);
        builder
            .when_transition()
            .when(local.selectors.is_jalr)
            .when(next.is_real)
            .assert_eq(next.fp, local.a.value()[0]);
        builder
            .when_transition()
            .when(one - is_jump_instruction)
            .when(next.is_real)
            .assert_eq(next.fp, local.fp);
    }
}
