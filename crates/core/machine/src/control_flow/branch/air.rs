use std::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_core_executor::{Opcode, DEFAULT_PC_INC, UNUSED_PC};
use sp1_stark::{
    air::{BaseAirBuilder, SP1AirBuilder},
    Word,
};

use crate::{air::WordAirBuilder, operations::BabyBearWordRangeChecker};

use super::{BranchChip, BranchColumns};

/// Verifies all the branching related columns.
///
/// It does this in few parts:
/// 1. It verifies that the next pc is correct based on the branching column.  That column is a
///    boolean that indicates whether the branch condition is true.
/// 2. It verifies the correct value of branching based on the helper bool columns (a_eq_b,
///    a_gt_b, a_lt_b).
/// 3. It verifier the correct values of the helper bool columns based on op_a and op_b.
///
impl<AB> Air<AB> for BranchChip
where
    AB: SP1AirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &BranchColumns<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);

        let opcode = local.is_beq * Opcode::BEQ.as_field::<AB::F>()
            + local.is_bne * Opcode::BNE.as_field::<AB::F>()
            + local.is_blt * Opcode::BLT.as_field::<AB::F>()
            + local.is_bge * Opcode::BGE.as_field::<AB::F>()
            + local.is_bltu * Opcode::BLTU.as_field::<AB::F>()
            + local.is_bgeu * Opcode::BGEU.as_field::<AB::F>();

        builder.receive_instruction(
            local.pc.reduce::<AB>(),
            local.next_pc.reduce::<AB>(),
            opcode,
            local.op_a_value,
            local.op_b_value,
            local.op_c_value,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_real,
        );

        // Evaluate program counter constraints.
        {
            // Range check branch_cols.pc and branch_cols.next_pc.
            BabyBearWordRangeChecker::<AB::F>::range_check(
                builder,
                local.pc,
                local.pc_range_checker,
                local.is_real.into(),
            );
            BabyBearWordRangeChecker::<AB::F>::range_check(
                builder,
                local.next_pc,
                local.next_pc_range_checker,
                local.is_real.into(),
            );

            // When we are branching, calculate branch_cols.next_pc <==> branch_cols.pc + c.
            builder.send_instruction(
                AB::Expr::from_canonical_u32(UNUSED_PC),
                AB::Expr::from_canonical_u32(UNUSED_PC + DEFAULT_PC_INC),
                Opcode::ADD.as_field::<AB::F>(),
                local.next_pc,
                local.pc,
                local.op_c_value,
                AB::Expr::zero(),
                local.next_pc_nonce,
                AB::Expr::zero(),
                local.is_branching,
            );

            // When we are not branching, assert that local.pc + 4 <==> next.pc.
            builder.when(local.is_real).when(local.not_branching).assert_eq(
                local.pc.reduce::<AB>() + AB::Expr::from_canonical_u32(DEFAULT_PC_INC),
                local.next_pc.reduce::<AB>(),
            );

            // When local.not_branching is true, assert that local.is_real is true.
            builder.when(local.not_branching).assert_one(local.is_real);

            // Assert that either we are branching or not branching when the instruction is a
            // branch.
            builder.when(local.is_real).assert_one(local.is_branching + local.not_branching);
            builder.when(local.is_real).assert_bool(local.is_branching);
            builder.when(local.is_real).assert_bool(local.not_branching);
        }

        // Evaluate branching value constraints.
        {
            // When the opcode is BEQ and we are branching, assert that a_eq_b is true.
            builder.when(local.is_beq * local.is_branching).assert_one(local.a_eq_b);

            // When the opcode is BEQ and we are not branching, assert that either a_gt_b or a_lt_b
            // is true.
            builder
                .when(local.is_beq)
                .when_not(local.is_branching)
                .assert_one(local.a_gt_b + local.a_lt_b);

            // When the opcode is BNE and we are branching, assert that either a_gt_b or a_lt_b is
            // true.
            builder.when(local.is_bne * local.is_branching).assert_one(local.a_gt_b + local.a_lt_b);

            // When the opcode is BNE and we are not branching, assert that a_eq_b is true.
            builder.when(local.is_bne).when_not(local.is_branching).assert_one(local.a_eq_b);

            // When the opcode is BLT or BLTU and we are branching, assert that a_lt_b is true.
            builder
                .when((local.is_blt + local.is_bltu) * local.is_branching)
                .assert_one(local.a_lt_b);

            // When the opcode is BLT or BLTU and we are not branching, assert that either a_eq_b
            // or a_gt_b is true.
            builder
                .when(local.is_blt + local.is_bltu)
                .when_not(local.is_branching)
                .assert_one(local.a_eq_b + local.a_gt_b);

            // When the opcode is BGE or BGEU and we are branching, assert that a_gt_b is true.
            builder
                .when((local.is_bge + local.is_bgeu) * local.is_branching)
                .assert_one(local.a_gt_b + local.a_eq_b);

            // When the opcode is BGE or BGEU and we are not branching, assert that either a_eq_b
            // or a_lt_b is true.
            builder
                .when(local.is_bge + local.is_bgeu)
                .when_not(local.is_branching)
                .assert_one(local.a_lt_b);
        }

        // When it's a branch instruction and a_eq_b, assert that a == b.
        builder
            .when(local.is_real * local.a_eq_b)
            .assert_word_eq(local.op_a_value, local.op_b_value);

        //  To prevent this ALU send to be arbitrarily large when is_branch_instruction is false.
        builder.when_not(local.is_real).assert_zero(local.is_branching);

        // Calculate a_lt_b <==> a < b (using appropriate signedness).
        let use_signed_comparison = local.is_blt + local.is_bge;
        builder.send_instruction(
            AB::Expr::from_canonical_u32(UNUSED_PC),
            AB::Expr::from_canonical_u32(UNUSED_PC + DEFAULT_PC_INC),
            use_signed_comparison.clone() * Opcode::SLT.as_field::<AB::F>()
                + (AB::Expr::one() - use_signed_comparison.clone())
                    * Opcode::SLTU.as_field::<AB::F>(),
            Word::extend_var::<AB>(local.a_lt_b),
            local.op_a_value,
            local.op_b_value,
            AB::Expr::zero(),
            local.a_lt_b_nonce,
            AB::Expr::zero(),
            local.is_real,
        );

        // Calculate a_gt_b <==> a > b (using appropriate signedness).
        builder.send_instruction(
            AB::Expr::from_canonical_u32(UNUSED_PC),
            AB::Expr::from_canonical_u32(UNUSED_PC + DEFAULT_PC_INC),
            use_signed_comparison.clone() * Opcode::SLT.as_field::<AB::F>()
                + (AB::Expr::one() - use_signed_comparison) * Opcode::SLTU.as_field::<AB::F>(),
            Word::extend_var::<AB>(local.a_gt_b),
            local.op_b_value,
            local.op_a_value,
            AB::Expr::zero(),
            local.a_gt_b_nonce,
            AB::Expr::zero(),
            local.is_real,
        );
    }
}
