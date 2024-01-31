pub mod branch;
pub mod memory;

use crate::air::{CurtaAirBuilder, WordAirBuilder};
use crate::cpu::columns::opcode::OpcodeSelectorCols;
use crate::cpu::columns::{AUIPCCols, CpuCols, JumpCols, MemoryColumns, NUM_CPU_COLS};
use crate::cpu::CpuChip;
use crate::memory::MemoryCols;
use crate::runtime::{AccessPosition, Opcode};

use core::borrow::Borrow;
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_field::AbstractField;
use p3_matrix::MatrixRowSlices;

use super::columns::{NUM_AUIPC_COLS, NUM_JUMP_COLS, NUM_MEMORY_COLUMNS};

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

        // Clock constraints.
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
            .assert_word_eq(local.op_b_val(), local.instruction.op_b);
        builder
            .when(local.selectors.imm_c)
            .assert_word_eq(local.op_c_val(), local.instruction.op_c);

        // // We always write to the first register unless we are doing a branch_op or a store_op.
        // // The multiplicity is 1-selectors.noop-selectors.reg_0_write (the case where we're trying to write to register 0).
        builder.constraint_memory_access(
            local.segment,
            local.clk + AB::F::from_canonical_u32(AccessPosition::A as u32),
            local.instruction.op_a[0],
            &local.op_a_access,
            AB::Expr::one() - local.selectors.is_noop - local.selectors.reg_0_write,
        );

        builder
            .when(is_branch_instruction.clone() + self.is_store_instruction::<AB>(&local.selectors))
            .assert_word_eq(local.op_a_val(), local.op_a_access.prev_value);

        // // We always read to register b and register c unless the imm_b or imm_c flags are set.
        // TODO: for these, we could save the "op_b_access.prev_value" column because it's always
        // a read and never a write.
        builder.constraint_memory_access(
            local.segment,
            local.clk + AB::F::from_canonical_u32(AccessPosition::B as u32),
            local.instruction.op_b[0],
            &local.op_b_access,
            AB::Expr::one() - local.selectors.imm_b,
        );
        builder
            .when(AB::Expr::one() - local.selectors.imm_b)
            .assert_word_eq(local.op_b_val(), *local.op_b_access.prev_value());

        builder.constraint_memory_access(
            local.segment,
            local.clk + AB::F::from_canonical_u32(AccessPosition::C as u32),
            local.instruction.op_c[0],
            &local.op_c_access,
            AB::Expr::one() - local.selectors.imm_c,
        );
        builder
            .when(AB::Expr::one() - local.selectors.imm_c)
            .assert_word_eq(local.op_c_val(), *local.op_c_access.prev_value());

        let memory_columns: MemoryColumns<AB::Var> =
            *local.opcode_specific_columns[..NUM_MEMORY_COLUMNS].borrow();

        builder.constraint_memory_access(
            local.segment,
            local.clk + AB::F::from_canonical_u32(AccessPosition::Memory as u32),
            memory_columns.addr_aligned,
            &memory_columns.memory_access,
            is_memory_instruction.clone(),
        );

        //////////////////////////////////////////

        // Check that reduce(addr_word) == addr_aligned + addr_offset
        builder
            .when(is_memory_instruction.clone())
            .assert_eq::<AB::Expr, AB::Expr>(
                memory_columns.addr_aligned + memory_columns.addr_offset,
                memory_columns.addr_word.reduce::<AB>(),
            );

        // Check that each addr_word element is a byte
        builder.slice_range_check_u8(&memory_columns.addr_word.0, is_memory_instruction.clone());

        // Send to the ALU table to verify correct calculation of addr_word
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            memory_columns.addr_word,
            local.op_b_val(),
            local.op_c_val(),
            is_memory_instruction.clone(),
        );

        self.eval_memory_load::<AB>(builder, local);

        self.eval_memory_store::<AB>(builder, local);

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
            local.op_a_val(),
            local.op_b_val(),
            local.op_c_val(),
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
    pub(crate) fn is_alu_instruction<AB: CurtaAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_alu.into()
    }

    pub(crate) fn jump_ops_eval<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Get the jump specific columns
        let jump_columns: JumpCols<AB::Var> =
            *local.opcode_specific_columns[..NUM_JUMP_COLS].borrow();

        // Verify that the local.pc + 4 is saved in op_a for both jump instructions.
        builder
            .when(local.selectors.is_jal + local.selectors.is_jalr)
            .assert_eq(
                local.op_a_val().reduce::<AB>(),
                local.pc + AB::F::from_canonical_u8(4),
            );

        // Verify that the word form of local.pc is correct for JAL instructions.
        builder
            .when(local.selectors.is_jal)
            .assert_eq(jump_columns.pc.reduce::<AB>(), local.pc);

        // Verify that the word form of next.pc is correct for both jump instructions.
        builder
            .when(local.selectors.is_jal + local.selectors.is_jalr)
            .assert_eq(jump_columns.next_pc.reduce::<AB>(), next.pc);

        // Verify that the new pc is calculated correctly for JAL instructions.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            jump_columns.next_pc,
            jump_columns.pc,
            local.op_b_val(),
            local.selectors.is_jal,
        );

        // Verify that the new pc is calculated correctly for JALR instructions.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            jump_columns.next_pc,
            local.op_b_val(),
            local.op_c_val(),
            local.selectors.is_jalr,
        );
    }

    pub(crate) fn auipc_eval<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) {
        // Get the auipc specific columns
        let auipc_columns: AUIPCCols<AB::Var> =
            *local.opcode_specific_columns[..NUM_AUIPC_COLS].borrow();

        // Verify that the word form of local.pc is correct.
        builder
            .when(local.selectors.is_auipc)
            .assert_eq(auipc_columns.pc.reduce::<AB>(), local.pc);

        // Verify that op_a == pc + op_b.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.op_a_val(),
            auipc_columns.pc,
            local.op_b_val(),
            local.selectors.is_auipc,
        );
    }
}
