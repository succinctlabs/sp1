use p3_air::AirBuilder;
use sp1_core::air::BaseAirBuilder;

use crate::{
    air::SP1RecursionAirBuilder,
    poseidon2_wide::{
        columns::{control_flow::ControlFlow, syscall_params::SyscallParams},
        Poseidon2WideChip,
    },
    runtime::Opcode,
};

impl<const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    /// Eval the syscall parameters.
    pub(crate) fn eval_syscall_params<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local_syscall: &SyscallParams<AB::Var>,
        next_syscall: &SyscallParams<AB::Var>,
        local_control_flow: &ControlFlow<AB::Var>,
        next_control_flow: &ControlFlow<AB::Var>,
        receive_syscall: AB::Var,
    ) {
        // Constraint that the operands are sent from the CPU table.
        let params = local_syscall.get_raw_params();
        let opcodes: [AB::Expr; 3] = [
            Opcode::Poseidon2Compress,
            Opcode::Poseidon2Absorb,
            Opcode::Poseidon2Finalize,
        ]
        .map(|x| x.as_field::<AB::F>().into());
        let opcode_selectors = [
            local_control_flow.is_compress,
            local_control_flow.is_absorb,
            local_control_flow.is_finalize,
        ];

        let used_opcode: AB::Expr = opcodes
            .iter()
            .zip(opcode_selectors.iter())
            .map(|(opcode, opcode_selector)| opcode.clone() * *opcode_selector)
            .sum();

        builder.receive_table(used_opcode, &params, receive_syscall);

        let mut transition_builder = builder.when_transition();

        // Verify that the syscall parameters are copied to the compress output row.
        {
            let mut compress_syscall_builder = transition_builder
                .when(local_control_flow.is_compress * local_control_flow.is_syscall_row);

            let local_syscall_params = local_syscall.compress();
            let next_syscall_params = next_syscall.compress();
            compress_syscall_builder.assert_eq(local_syscall_params.clk, next_syscall_params.clk);
            compress_syscall_builder
                .assert_eq(local_syscall_params.dst_ptr, next_syscall_params.dst_ptr);
            compress_syscall_builder
                .assert_eq(local_syscall_params.left_ptr, next_syscall_params.left_ptr);
            compress_syscall_builder.assert_eq(
                local_syscall_params.right_ptr,
                next_syscall_params.right_ptr,
            );
        }

        // Verify that the syscall parameters are copied down to all the non syscall absorb rows.
        {
            let mut absorb_syscall_builder = transition_builder.when(local_control_flow.is_absorb);
            let mut absorb_syscall_builder =
                absorb_syscall_builder.when_not(next_control_flow.is_syscall_row);

            let local_syscall_params = local_syscall.absorb();
            let next_syscall_params = next_syscall.absorb();

            absorb_syscall_builder.assert_eq(local_syscall_params.clk, next_syscall_params.clk);
            absorb_syscall_builder.assert_eq(
                local_syscall_params.hash_and_absorb_num,
                next_syscall_params.hash_and_absorb_num,
            );
            absorb_syscall_builder.assert_eq(
                local_syscall_params.input_ptr,
                next_syscall_params.input_ptr,
            );
            absorb_syscall_builder.assert_eq(
                local_syscall_params.input_len,
                next_syscall_params.input_len,
            );
        }
    }
}
