use crate::air::{reduce, CurtaAirBuilder};
use crate::cpu::cols::cpu_cols::{
    AUIPCColumns, BranchColumns, CpuCols, JumpColumns, MemoryColumns, NUM_CPU_COLS,
};
use crate::cpu::cols::opcode_cols::OpcodeSelectors;
use crate::cpu::CpuChip;

use core::borrow::Borrow;
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_field::AbstractField;
use p3_matrix::MatrixRowSlices;
use std::mem::transmute_copy;

use crate::runtime::{AccessPosition, Opcode};

impl<F> BaseAir<F> for CpuChip {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}

impl<AB> Air<AB> for CpuChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &CpuCols<AB::Var> = main.row_slice(0).borrow();
        let next: &CpuCols<AB::Var> = main.row_slice(1).borrow();

        // Dummy constraint of degree 3.
        builder.assert_eq(
            local.pc * local.pc * local.pc,
            local.pc * local.pc * local.pc,
        );

        builder.assert_bool(local.is_real);

        // Clock constraints
        builder.when_first_row().assert_one(local.clk);

        // TODO: handle precompile dynamic clk
        // builder
        //     .when_transition()
        //     .assert_eq(local.clk + AB::F::from_canonical_u32(4), next.clk);

        // Contrain the interaction with program table
        builder.send_program(local.pc, local.instruction, local.selectors, local.is_real);

        let is_memory_instruction: AB::Expr = self.is_memory_instruction::<AB>(&local.selectors);
        let is_branch_instruction: AB::Expr = self.is_branch_instruction::<AB>(&local.selectors);
        let is_alu_instruction: AB::Expr = self.is_alu_instruction::<AB>(&local.selectors);

        //////////////////////////////////////////

        // Constraint op_a_val, op_b_val, op_c_val
        // Constraint the op_b_val and op_c_val columns when imm_b and imm_c are true.
        builder
            .when(local.selectors.imm_b)
            .assert_word_eq(*local.op_b_val(), local.instruction.op_b);
        builder
            .when(local.selectors.imm_c)
            .assert_word_eq(*local.op_c_val(), local.instruction.op_c);

        // // We always write to the first register unless we are doing a branch_op or a store_op.
        // // The multiplicity is 1-selectors.noop-selectors.reg_0_write (the case where we're trying to write to register 0).
        builder.constraint_memory_access(
            local.segment,
            local.clk + AB::F::from_canonical_u32(AccessPosition::A as u32),
            local.instruction.op_a[0],
            local.op_a_access,
            AB::Expr::one() - local.selectors.is_noop - local.selectors.reg_0_write,
        );

        builder
            .when(is_branch_instruction.clone() + self.is_store::<AB>(&local.selectors))
            .assert_word_eq(*local.op_a_val(), local.op_a_access.prev_value);

        // // We always read to register b and register c unless the imm_b or imm_c flags are set.
        // TODO: for these, we could save the "op_b_access.prev_value" column because it's always
        // a read and never a write.
        builder.constraint_memory_access(
            local.segment,
            local.clk + AB::F::from_canonical_u32(AccessPosition::B as u32),
            local.instruction.op_b[0],
            local.op_b_access,
            AB::Expr::one() - local.selectors.imm_b,
        );
        builder
            .when(AB::Expr::one() - local.selectors.imm_b)
            .assert_word_eq(*local.op_b_val(), local.op_b_access.prev_value);

        builder.constraint_memory_access(
            local.segment,
            local.clk + AB::F::from_canonical_u32(AccessPosition::C as u32),
            local.instruction.op_c[0],
            local.op_c_access,
            AB::Expr::one() - local.selectors.imm_c,
        );
        builder
            .when(AB::Expr::one() - local.selectors.imm_c)
            .assert_word_eq(*local.op_c_val(), local.op_c_access.prev_value);

        let memory_columns: MemoryColumns<AB::Var> =
            unsafe { transmute_copy(&local.opcode_specific_columns) };

        builder.constraint_memory_access(
            local.segment,
            local.clk + AB::F::from_canonical_u32(AccessPosition::Memory as u32),
            memory_columns.addr_aligned,
            memory_columns.memory_access,
            is_memory_instruction.clone(),
        );

        //////////////////////////////////////////

        // Check that reduce(addr_word) == addr_aligned + addr_offset
        builder
            .when(is_memory_instruction.clone())
            .assert_eq::<AB::Expr, AB::Expr>(
                memory_columns.addr_aligned + memory_columns.addr_offset,
                reduce::<AB>(memory_columns.addr_word),
            );

        // Check that each addr_word element is a byte
        builder.range_check_word(memory_columns.addr_word, is_memory_instruction.clone());

        // Send to the ALU table to verify correct calculation of addr_word
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            memory_columns.addr_word,
            *local.op_b_val(),
            *local.op_c_val(),
            is_memory_instruction.clone(),
        );

        self.load_memory_eval::<AB>(builder, local);

        self.store_memory_eval::<AB>(builder, local);

        //////////////////////////////////////////

        //// Branch instructions
        self.branch_ops_eval::<AB>(builder, is_branch_instruction.clone(), local, next);

        //// Jump instructions
        self.jump_ops_eval::<AB>(builder, local, next);

        //// AUIPC instruction
        self.auipc_eval(builder, local);

        //// ALU instructions
        builder.send_alu(
            local.instruction.opcode,
            *local.op_a_val(),
            *local.op_b_val(),
            *local.op_c_val(),
            is_alu_instruction,
        );

        // TODO:  Need to handle HALT ecall
        // For all non branch or jump instructions, verify that next.pc == pc + 4
        // builder
        //     .when_not(is_branch_instruction + local.selectors.is_jal + local.selectors.is_jalr)
        //     .assert_eq(local.pc + AB::Expr::from_canonical_u8(4), next.pc);
    }
}

impl CpuChip {
    fn is_alu_instruction<AB: CurtaAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectors<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_add
            + opcode_selectors.is_sub
            + opcode_selectors.is_mul
            + opcode_selectors.is_div
            + opcode_selectors.is_shift
            + opcode_selectors.is_bitwise
            + opcode_selectors.is_lt
    }

    fn is_branch_instruction<AB: CurtaAirBuilder>(
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

    fn branch_ops_eval<AB: CurtaAirBuilder>(
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
            .assert_eq(reduce::<AB>(branch_columns.pc), local.pc);

        // Verify that branch_columns.next_pc is correct.  That is next.pc in WORD form.
        builder
            .when(local.branching)
            .assert_eq(reduce::<AB>(branch_columns.next_pc), next.pc);

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
            .when(is_branch_instruction.clone())
            .when_not(local.branching)
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
            .assert_one(branch_columns.a_gt_b);

        builder
            .when(local.selectors.is_bge + local.selectors.is_bgeu)
            .when_not(local.branching)
            .assert_one(branch_columns.a_eq_b + branch_columns.a_lt_b);

        //// Check that the helper bools' value is correct.
        builder
            .when(is_branch_instruction.clone() * branch_columns.a_eq_b)
            .assert_word_eq(*local.op_a_val(), *local.op_b_val());

        let use_signed_comparison = local.selectors.is_blt + local.selectors.is_bge;
        builder.send_alu(
            use_signed_comparison.clone() * AB::Expr::from_canonical_u8(Opcode::SLT as u8)
                + (AB::Expr::one() - use_signed_comparison.clone())
                    * AB::Expr::from_canonical_u8(Opcode::SLTU as u8),
            AB::extend_expr_to_word(branch_columns.a_lt_b),
            *local.op_a_val(),
            *local.op_b_val(),
            is_branch_instruction.clone(),
        );

        builder.send_alu(
            use_signed_comparison.clone() * AB::Expr::from_canonical_u8(Opcode::SLT as u8)
                + (AB::Expr::one() - use_signed_comparison)
                    * AB::Expr::from_canonical_u8(Opcode::SLTU as u8),
            AB::extend_expr_to_word(branch_columns.a_gt_b),
            *local.op_b_val(),
            *local.op_a_val(),
            is_branch_instruction.clone(),
        );
    }

    fn jump_ops_eval<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Get the jump specific columns
        let jump_columns: JumpColumns<AB::Var> =
            unsafe { transmute_copy(&local.opcode_specific_columns) };

        // Verify that the local.pc + 4 is saved in op_a for both jump instructions.
        builder
            .when(local.selectors.is_jal + local.selectors.is_jalr)
            .assert_eq(
                reduce::<AB>(*local.op_a_val()),
                local.pc + AB::F::from_canonical_u8(4),
            );

        // Verify that the word form of local.pc is correct for JAL instructions.
        builder
            .when(local.selectors.is_jal)
            .assert_eq(reduce::<AB>(jump_columns.pc), local.pc);

        // Verify that the word form of next.pc is correct for both jump instructions.
        builder
            .when(local.selectors.is_jal + local.selectors.is_jalr)
            .assert_eq(reduce::<AB>(jump_columns.next_pc), next.pc);

        // Verify that the new pc is calculated correctly for JAL instructions.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            jump_columns.next_pc,
            jump_columns.pc,
            *local.op_b_val(),
            local.selectors.is_jal,
        );

        // Verify that the new pc is calculated correctly for JALR instructions.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            jump_columns.next_pc,
            *local.op_b_val(),
            *local.op_c_val(),
            local.selectors.is_jalr,
        );
    }

    fn auipc_eval<AB: CurtaAirBuilder>(&self, builder: &mut AB, local: &CpuCols<AB::Var>) {
        // Get the auipc specific columns
        let auipc_columns: AUIPCColumns<AB::Var> =
            unsafe { transmute_copy(&local.opcode_specific_columns) };

        // Verify that the word form of local.pc is correct.
        builder
            .when(local.selectors.is_auipc)
            .assert_eq(reduce::<AB>(auipc_columns.pc), local.pc);

        // Verify that op_a == pc + op_b.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            *local.op_a_val(),
            auipc_columns.pc,
            *local.op_b_val(),
            local.selectors.is_auipc,
        );
    }
}
