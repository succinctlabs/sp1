use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};

use crate::{
    air::{Block, BlockBuilder, SP1RecursionAirBuilder},
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
        let is_jump_instr = self.is_jump_instruction::<AB>(local);

        // Verify the next row's fp.
        builder
            .when_first_row()
            .assert_eq(local.fp, F::from_canonical_usize(STACK_SIZE));
        let not_jump_instruction = AB::Expr::one() - is_jump_instr.clone();
        let expected_next_fp = local.selectors.is_jal * (local.fp + local.c.value()[0])
            + local.selectors.is_jalr * local.c.value()[0]
            + not_jump_instruction * local.fp;
        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(next.fp, expected_next_fp);

        // Verify the a operand values.
        let expected_a_val = local.selectors.is_jal * local.pc
            + local.selectors.is_jalr * (local.pc + AB::Expr::one());
        let expected_a_val_block = Block::from(expected_a_val);
        builder
            .when(is_jump_instr)
            .assert_block_eq(*local.a.value(), expected_a_val_block);

        // Add to the `next_pc` expression.
        *next_pc += local.selectors.is_jal * (local.pc + local.b.value()[0]);
        *next_pc += local.selectors.is_jalr * local.b.value()[0];
    }
}
