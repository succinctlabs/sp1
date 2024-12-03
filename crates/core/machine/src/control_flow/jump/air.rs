use std::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_core_executor::{Opcode, DEFAULT_PC_INC, UNUSED_PC};
use sp1_stark::air::{BaseAirBuilder, SP1AirBuilder};

use crate::operations::BabyBearWordRangeChecker;

use super::{JumpChip, JumpColumns};

impl<AB> Air<AB> for JumpChip
where
    AB: SP1AirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &JumpColumns<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_jal);
        builder.assert_bool(local.is_jalr);
        let is_real = local.is_jal + local.is_jalr;
        builder.assert_bool(is_real.clone());

        let opcode = local.is_jal * Opcode::JAL.as_field::<AB::F>()
            + local.is_jalr * Opcode::JALR.as_field::<AB::F>();

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
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            is_real.clone(),
        );

        // Verify that the local.pc + 4 is saved in op_a for both jump instructions.
        // When op_a is set to register X0, the RISC-V spec states that the jump instruction will
        // not have a return destination address (it is effectively a GOTO command).  In this case,
        // we shouldn't verify the return address.
        builder.when(is_real.clone()).when_not(local.op_a_0).assert_eq(
            local.op_a_value.reduce::<AB>(),
            local.pc.reduce::<AB>() + AB::F::from_canonical_u32(DEFAULT_PC_INC),
        );

        // Range check op_a, pc, and next_pc.
        BabyBearWordRangeChecker::<AB::F>::range_check(
            builder,
            local.op_a_value,
            local.op_a_range_checker,
            is_real.clone(),
        );
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
            is_real,
        );

        // Verify that the new pc is calculated correctly for JAL instructions.
        builder.send_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::from_canonical_u32(UNUSED_PC),
            AB::Expr::from_canonical_u32(UNUSED_PC + DEFAULT_PC_INC),
            AB::Expr::zero(),
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.next_pc,
            local.pc,
            local.op_b_value,
            AB::Expr::zero(),
            local.jal_nonce,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_jal,
        );

        // Verify that the new pc is calculated correctly for JALR instructions.
        builder.send_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::from_canonical_u32(UNUSED_PC),
            AB::Expr::from_canonical_u32(UNUSED_PC + DEFAULT_PC_INC),
            AB::Expr::zero(),
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.next_pc,
            local.op_b_value,
            local.op_c_value,
            AB::Expr::zero(),
            local.jalr_nonce,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_jalr,
        );
    }
}
