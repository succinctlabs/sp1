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

        // SAFETY: All selectors `is_beq`, `is_bne`, `is_blt`, `is_bge`, `is_bltu`, `is_bgeu` are checked to be boolean.
        // Each "real" row has exactly one selector turned on, as `is_real`, the sum of the six selectors, is boolean.
        // Therefore, the `opcode` matches the corresponding opcode.
        builder.assert_bool(local.is_beq);
        builder.assert_bool(local.is_bne);
        builder.assert_bool(local.is_blt);
        builder.assert_bool(local.is_bge);
        builder.assert_bool(local.is_bltu);
        builder.assert_bool(local.is_bgeu);
        let is_real = local.is_beq
            + local.is_bne
            + local.is_blt
            + local.is_bge
            + local.is_bltu
            + local.is_bgeu;
        builder.assert_bool(is_real.clone());

        let opcode = local.is_beq * Opcode::BEQ.as_field::<AB::F>()
            + local.is_bne * Opcode::BNE.as_field::<AB::F>()
            + local.is_blt * Opcode::BLT.as_field::<AB::F>()
            + local.is_bge * Opcode::BGE.as_field::<AB::F>()
            + local.is_bltu * Opcode::BLTU.as_field::<AB::F>()
            + local.is_bgeu * Opcode::BGEU.as_field::<AB::F>();

        // SAFETY: This checks the following.
        // - `num_extra_cycles = 0`
        // - `op_a_val` will be constrained in the CpuChip as `op_a_immutable = 1`
        // - `op_a_immutable = 1`, as this is a branch instruction
        // - `is_memory = 0`
        // - `is_syscall = 0`
        // - `is_halt = 0`
        // `next_pc` still has to be constrained, and this is done below.
        builder.receive_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.pc.reduce::<AB>(),
            local.next_pc.reduce::<AB>(),
            AB::Expr::zero(),
            opcode,
            local.op_a_value,
            local.op_b_value,
            local.op_c_value,
            local.op_a_0,
            AB::Expr::one(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            is_real.clone(),
        );

        // Evaluate program counter constraints.
        {
            // Range check branch_cols.pc and branch_cols.next_pc.
            // SAFETY: `is_real` is already checked to be boolean.
            // The `BabyBearWordRangeChecker` assumes that the value is checked to be a valid word.
            // This is done when the word form is relevant, i.e. when `pc` and `next_pc` are sent to the ADD ALU table.
            // The ADD ALU table checks the inputs are valid words, when it invokes `AddOperation`.
            BabyBearWordRangeChecker::<AB::F>::range_check(
                builder,
                local.pc,
                local.pc_range_checker,
                is_real.clone(),
            );
            BabyBearWordRangeChecker::<AB::F>::range_check(
                builder,
                local.next_pc,
                local.next_pc_range_checker,
                is_real.clone(),
            );

            // When we are branching, assert that local.next_pc <==> local.pc + c.
            builder.send_instruction(
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::from_canonical_u32(UNUSED_PC),
                AB::Expr::from_canonical_u32(UNUSED_PC + DEFAULT_PC_INC),
                AB::Expr::zero(),
                Opcode::ADD.as_field::<AB::F>(),
                local.next_pc,
                local.pc,
                local.op_c_value,
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
                local.is_branching,
            );

            // When we are not branching, assert that local.pc + 4 <==> next.pc.
            builder.when(is_real.clone()).when(local.not_branching).assert_eq(
                local.pc.reduce::<AB>() + AB::Expr::from_canonical_u32(DEFAULT_PC_INC),
                local.next_pc.reduce::<AB>(),
            );

            // When local.not_branching is true, assert that local.is_real is true.
            builder.when(local.not_branching).assert_one(is_real.clone());

            // To prevent the ALU send above to be non-zero when the row is a padding row.
            builder.when_not(is_real.clone()).assert_zero(local.is_branching);

            // Assert that either we are branching or not branching when the instruction is a
            // branch.
            // The `next_pc` is constrained in both branching and not branching cases, so it is fully constrained.
            builder.when(is_real.clone()).assert_one(local.is_branching + local.not_branching);
            builder.when(is_real.clone()).assert_bool(local.is_branching);
            builder.when(is_real.clone()).assert_bool(local.not_branching);
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
            .when(is_real.clone() * local.a_eq_b)
            .assert_word_eq(local.op_a_value, local.op_b_value);

        // Calculate a_lt_b <==> a < b (using appropriate signedness).
        // SAFETY: `use_signed_comparison` is boolean, since at most one selector is turned on.
        let use_signed_comparison = local.is_blt + local.is_bge;
        builder.send_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::from_canonical_u32(UNUSED_PC),
            AB::Expr::from_canonical_u32(UNUSED_PC + DEFAULT_PC_INC),
            AB::Expr::zero(),
            use_signed_comparison.clone() * Opcode::SLT.as_field::<AB::F>()
                + (AB::Expr::one() - use_signed_comparison.clone())
                    * Opcode::SLTU.as_field::<AB::F>(),
            Word::extend_var::<AB>(local.a_lt_b),
            local.op_a_value,
            local.op_b_value,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            is_real.clone(),
        );

        // Calculate a_gt_b <==> a > b (using appropriate signedness).
        builder.send_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::from_canonical_u32(UNUSED_PC),
            AB::Expr::from_canonical_u32(UNUSED_PC + DEFAULT_PC_INC),
            AB::Expr::zero(),
            use_signed_comparison.clone() * Opcode::SLT.as_field::<AB::F>()
                + (AB::Expr::one() - use_signed_comparison) * Opcode::SLTU.as_field::<AB::F>(),
            Word::extend_var::<AB>(local.a_gt_b),
            local.op_b_value,
            local.op_a_value,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            is_real.clone(),
        );
    }
}
