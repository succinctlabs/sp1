use crate::{
    adapter::{register::j_type::JTypeReader, state::CPUState},
    air::{SP1CoreAirBuilder, SP1Operation},
    eval_untrusted_program,
    operations::{AddOperation, AddOperationInput},
    TrustMode, UserMode,
};
use slop_air::{Air, AirBuilder};
use slop_algebra::{AbstractField, Field};
use slop_matrix::Matrix;
use sp1_core_executor::{ByteOpcode, Opcode, CLK_INC};
use sp1_hypercube::Word;
use std::borrow::Borrow;

use super::{JalChip, JalColumns};

impl<AB, M> Air<AB> for JalChip<M>
where
    AB: SP1CoreAirBuilder,
    AB::Var: Sized,
    M: TrustMode,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &JalColumns<AB::Var, M> = (*local).borrow();

        builder.assert_bool(local.is_real);

        let opcode = Opcode::JAL.as_field::<AB::F>();
        let funct3 = AB::Expr::from_canonical_u8(Opcode::JAL.funct3().unwrap_or(0));
        let funct7 = AB::Expr::from_canonical_u8(Opcode::JAL.funct7().unwrap_or(0));
        let base_opcode = AB::Expr::from_canonical_u32(Opcode::JAL.base_opcode().0);
        let instr_type = AB::Expr::from_canonical_u32(Opcode::JAL.instruction_type().0 as u32);

        // We constrain `next_pc` to be the sum of `pc` and `op_b`.
        let op_input = AddOperationInput::<AB>::new(
            Word([
                local.state.pc[0].into(),
                local.state.pc[1].into(),
                local.state.pc[2].into(),
                AB::Expr::zero(),
            ]),
            local.adapter.b().map(|x| x.into()),
            local.add_operation,
            local.is_real.into(),
        );
        <AddOperation<AB::F> as SP1Operation<AB>>::eval(builder, op_input);

        let next_pc = local.add_operation.value;
        builder.assert_zero(next_pc[3]);

        // Check that the `next_pc` value is a multiple of 4.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            next_pc[0].into() * AB::F::from_canonical_u32(4).inverse(),
            AB::Expr::from_canonical_u32(14),
            AB::Expr::zero(),
            local.is_real,
        );

        // Constrain the state of the CPU.
        // The `next_pc` is constrained by the AIR.
        // The clock is incremented by `8`.
        CPUState::<AB::F>::eval(
            builder,
            local.state,
            [next_pc[0].into(), next_pc[1].into(), next_pc[2].into()],
            AB::Expr::from_canonical_u32(CLK_INC),
            local.is_real.into(),
        );

        builder.when_not(local.is_real).assert_zero(local.adapter.op_a_0);

        let op_input = AddOperationInput::<AB>::new(
            Word([
                local.state.pc[0].into(),
                local.state.pc[1].into(),
                local.state.pc[2].into(),
                AB::Expr::zero(),
            ]),
            Word([
                AB::Expr::from_canonical_u16(4),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
            ]),
            local.op_a_operation,
            local.is_real.into() - local.adapter.op_a_0,
        );
        <AddOperation<AB::F> as SP1Operation<AB>>::eval(builder, op_input);
        builder.assert_zero(local.op_a_operation.value[3]);
        for i in 0..3 {
            builder.when(local.adapter.op_a_0).assert_zero(local.op_a_operation.value[i]);
        }

        let mut is_trusted: AB::Expr = local.is_real.into();

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );

        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &JalColumns<AB::Var, UserMode> = (*local).borrow();

            let instruction = local.adapter.instruction::<AB>(opcode);

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);

            eval_untrusted_program(
                builder,
                local.state.pc,
                instruction,
                [instr_type, base_opcode, funct3, funct7],
                [local.state.clk_high::<AB>(), local.state.clk_low::<AB>()],
                local.is_real.into(),
                local.adapter_cols,
            );

            is_trusted = local.adapter_cols.is_trusted.into();
        }

        // Constrain the program and register reads.
        // Verify that the local.pc + 4 is saved in op_a for both jump instructions.
        // When op_a is set to register X0, the RISC-V spec states that the jump instruction will
        // not have a return destination address (it is effectively a GOTO command).  In this case,
        // we shouldn't verify the return address.
        JTypeReader::<AB::F>::eval(
            builder,
            local.state.clk_high::<AB>(),
            local.state.clk_low::<AB>(),
            local.state.pc,
            Opcode::JAL.as_field::<AB::F>(),
            local.op_a_operation.value,
            local.adapter,
            local.is_real.into(),
            is_trusted,
        );
    }
}
