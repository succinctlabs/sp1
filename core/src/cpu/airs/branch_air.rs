use std::mem::transmute_copy;

use p3_air::AirBuilder;
use p3_field::AbstractField;

use crate::{
    air::{BaseAirBuilder, CurtaAirBuilder, Word, WordAirBuilder},
    cpu::{
        cols::{
            cpu_cols::{BranchColumns, CpuCols},
            opcode_cols::OpcodeSelectors,
        },
        CpuChip,
    },
    runtime::Opcode,
};

impl CpuChip {
    pub(crate) fn is_branch_instruction<AB: CurtaAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectors<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_beq
            + opcode_selectors.is_bne
            + opcode_selectors.is_blt
            + opcode_selectors.is_bge
            + opcode_selectors.is_bltu
            + opcode_selectors.is_bgeu
    }

    pub(crate) fn branch_ops_eval<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        is_branch_instruction: AB::Expr,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        //// This function will verify all the branching related columns.
        // It does this in few parts.
        // 1. It verifies that the next pc is correct based on the branching column.  That column
        //    is a boolean that indicates whether the branch condition is true.
        // 2. It verifies the correct value of branching based on the helper bool columns (a_eq_b,
        //    a_gt_b, a_lt_b).
        // 3. It verifier the correct values of the helper bool columns based on op_a and op_b.

        // Get the branch specific columns
        let branch_columns: BranchColumns<AB::Var> =
            unsafe { transmute_copy(&local.opcode_specific_columns) };

        //// Check that the new pc is calculated correctly.
        // First handle the case when local.branching == true

        // Verify that branch_columns.pc is correct.  That is local.pc in WORD form.
        // Note that when local.branching == True, then is_branch_instruction == True.
        builder
            .when(local.branching)
            .assert_eq(branch_columns.pc.reduce::<AB>(), local.pc);

        // Verify that branch_columns.next_pc is correct.  That is next.pc in WORD form.
        builder
            .when(local.branching)
            .assert_eq(branch_columns.next_pc.reduce::<AB>(), next.pc);

        // Calculate the new pc via the ADD chip if local.branching == true
        builder.send_alu(
            AB::Expr::from_canonical_u8(Opcode::ADD as u8),
            branch_columns.next_pc,
            branch_columns.pc,
            *local.op_c_val(),
            local.branching,
            // Note that if local.branching == 1 => is_branch_instruction == 1
            // We can't have an ADD clause of condition/selector columns here, since that would
            // require a multiply which would have a degree of > 1 (the max degree allowable for
            // 'multiplicity').
        );

        // Check that pc + 4 == next_pc if local.branching == false
        builder
            .when(local.not_branching)
            .when_transition()
            .when(next.is_real)
            .assert_eq(local.pc + AB::Expr::from_canonical_u8(4), next.pc);

        //// Check that the branching value is correct

        // Boolean range check local.branching
        builder
            .when(is_branch_instruction.clone())
            .assert_bool(local.branching);

        // Check that branching value is correct based on the opcode and the helper bools.
        builder
            .when(local.selectors.is_beq * local.branching)
            .assert_one(branch_columns.a_eq_b);
        builder
            .when(local.selectors.is_beq)
            .when_not(local.branching)
            .assert_one(branch_columns.a_gt_b + branch_columns.a_lt_b);

        builder
            .when(local.selectors.is_bne * local.branching)
            .assert_one(branch_columns.a_gt_b + branch_columns.a_lt_b);
        builder
            .when(local.selectors.is_bne)
            .when_not(local.branching)
            .assert_one(branch_columns.a_eq_b);

        builder
            .when((local.selectors.is_blt + local.selectors.is_bltu) * local.branching)
            .assert_one(branch_columns.a_lt_b);
        builder
            .when(local.selectors.is_blt + local.selectors.is_bltu)
            .when_not(local.branching)
            .assert_one(branch_columns.a_eq_b + branch_columns.a_gt_b);

        builder
            .when((local.selectors.is_bge + local.selectors.is_bgeu) * local.branching)
            .assert_one(branch_columns.a_eq_b + branch_columns.a_gt_b);

        builder
            .when(local.selectors.is_bge + local.selectors.is_bgeu)
            .when_not(local.branching)
            .assert_one(branch_columns.a_lt_b);

        //// Check that the helper bools' value is correct.
        builder
            .when(is_branch_instruction.clone() * branch_columns.a_eq_b)
            .assert_word_eq(*local.op_a_val(), *local.op_b_val());

        let use_signed_comparison = local.selectors.is_blt + local.selectors.is_bge;
        builder.send_alu(
            use_signed_comparison.clone() * AB::Expr::from_canonical_u8(Opcode::SLT as u8)
                + (AB::Expr::one() - use_signed_comparison.clone())
                    * AB::Expr::from_canonical_u8(Opcode::SLTU as u8),
            Word::extend_var::<AB>(branch_columns.a_lt_b),
            *local.op_a_val(),
            *local.op_b_val(),
            is_branch_instruction.clone(),
        );

        builder.send_alu(
            use_signed_comparison.clone() * AB::Expr::from_canonical_u8(Opcode::SLT as u8)
                + (AB::Expr::one() - use_signed_comparison)
                    * AB::Expr::from_canonical_u8(Opcode::SLTU as u8),
            Word::extend_var::<AB>(branch_columns.a_gt_b),
            *local.op_b_val(),
            *local.op_a_val(),
            is_branch_instruction.clone(),
        );
    }
}
