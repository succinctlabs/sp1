use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};
use sp1_core::air::{BinomialExtension, ExtensionAirBuilder};

use crate::{
    air::{
        BinomialExtensionUtils, Block, BlockBuilder, IsExtZeroOperation, SP1RecursionAirBuilder,
    },
    cpu::{CpuChip, CpuCols},
    memory::MemoryCols,
};

impl<F: Field, const L: usize> CpuChip<F, L> {
    /// Eval the BRANCH operations.
    pub fn eval_branch<AB>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next_pc: &mut AB::Expr,
    ) where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        let branch_cols = local.opcode_specific.branch();
        let is_branch_instruction = self.is_branch_instruction::<AB>(local);
        let one = AB::Expr::one();

        // Convert operand values from Block<Var> to BinomialExtension<Expr>.  Note that it gets the
        // previous value of the `a` and `b` operands, since BNENIC will modify `a`.
        let a_prev_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.a.prev_value().map(|x| x.into()));
        let a_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.a.value().map(|x| x.into()));
        let b_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.b.value().map(|x| x.into()));
        let one_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(Block::from(one.clone()));

        let expected_a_ext = a_prev_ext + one_ext;

        // If the instruction is a BNEINC, verify that the a value is incremented by one.
        builder
            .when(local.is_real)
            .when(local.selectors.is_bneinc)
            .assert_block_eq(a_ext.as_block(), expected_a_ext.as_block());

        let comparison_diff = a_ext - b_ext;

        // Verify branch_cols.camparison_diff col.
        builder.when(is_branch_instruction.clone()).assert_ext_eq(
            BinomialExtension::from(branch_cols.comparison_diff_val),
            comparison_diff,
        );

        // Verify branch_cols.comparison_diff.result col.
        IsExtZeroOperation::<AB::F>::eval(
            builder,
            BinomialExtension::from(branch_cols.comparison_diff_val),
            branch_cols.comparison_diff,
            is_branch_instruction.clone(),
        );

        // Verify branch_col.do_branch col.
        let mut do_branch = local.selectors.is_beq * branch_cols.comparison_diff.result;
        do_branch += local.selectors.is_bne * (one.clone() - branch_cols.comparison_diff.result);
        do_branch += local.selectors.is_bneinc * (one.clone() - branch_cols.comparison_diff.result);
        builder
            .when(is_branch_instruction.clone())
            .assert_eq(branch_cols.do_branch, do_branch);

        // Verify branch_col.next_pc col.
        let pc_offset = local.c.value().0[0];
        let expected_next_pc =
            builder.if_else(branch_cols.do_branch, local.pc + pc_offset, local.pc + one);
        builder
            .when(is_branch_instruction.clone())
            .assert_eq(branch_cols.next_pc, expected_next_pc);

        // Add to the `next_pc` expression.
        *next_pc = is_branch_instruction * branch_cols.next_pc;
    }
}
