use p3_air::AirBuilder;
use p3_field::AbstractField;

use crate::{
    air::BaseAirBuilder,
    cpu::{aux::columns::CpuAuxCols, CpuAuxChip},
    operations::BabyBearWordRangeChecker,
    runtime::Opcode,
    stark::SP1AirBuilder,
};

impl CpuAuxChip {
    /// Constraints related to jump operations.
    pub(crate) fn eval_jump_ops<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuAuxCols<AB::Var>,
    ) {
        // Get the jump specific columns
        let jump_columns = local.opcode_specific_columns.jump();

        let is_jump_instruction = local.selectors.is_jal + local.selectors.is_jalr;

        // Verify that the local.pc + 4 is saved in op_a for both jump instructions.
        // When op_a is set to register X0, the RISC-V spec states that the jump instruction will
        // not have a return destination address (it is effectively a GOTO command).  In this case,
        // we shouldn't verify the return address.
        builder
            .when(is_jump_instruction.clone())
            .when_not(local.op_a_0)
            .assert_eq(
                local.op_a_val.reduce::<AB>(),
                local.pc + AB::F::from_canonical_u8(4),
            );

        // Verify that the word form of local.pc is correct for JAL instructions.
        builder
            .when(local.selectors.is_jal)
            .assert_eq(jump_columns.pc.reduce::<AB>(), local.pc);

        // When the last row is real and it's a jump instruction, assert that local.next_pc <==> jump_column.next_pc
        builder
            .when(local.is_real)
            .when(is_jump_instruction.clone())
            .assert_eq(jump_columns.next_pc.reduce::<AB>(), local.next_pc);

        // Range check op_a, pc, and next_pc.
        BabyBearWordRangeChecker::<AB::F>::range_check(
            builder,
            local.op_a_val,
            jump_columns.op_a_range_checker,
            is_jump_instruction.clone(),
        );
        BabyBearWordRangeChecker::<AB::F>::range_check(
            builder,
            jump_columns.pc,
            jump_columns.pc_range_checker,
            local.selectors.is_jal.into(),
        );
        BabyBearWordRangeChecker::<AB::F>::range_check(
            builder,
            jump_columns.next_pc,
            jump_columns.next_pc_range_checker,
            is_jump_instruction.clone(),
        );

        // Verify that the new pc is calculated correctly for JAL instructions.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            jump_columns.next_pc,
            jump_columns.pc,
            local.op_b_val,
            local.shard,
            local.channel,
            jump_columns.jal_nonce,
            local.selectors.is_jal,
        );

        // Verify that the new pc is calculated correctly for JALR instructions.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            jump_columns.next_pc,
            local.op_b_val,
            local.op_c_val,
            local.shard,
            local.channel,
            jump_columns.jalr_nonce,
            local.selectors.is_jalr,
        );
    }
}
