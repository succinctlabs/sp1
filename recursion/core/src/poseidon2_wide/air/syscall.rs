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
    pub(crate) fn eval_syscall_params<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local_syscall: &SyscallParams<AB::Var>,
        next_syscall: &SyscallParams<AB::Var>,
        local_control_flow: &ControlFlow<AB::Var>,
        next_control_flow: &ControlFlow<AB::Var>,
    ) {
        // Constraint that the operands are sent from the CPU table.
        let operands = local_syscall.get_raw_params();
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

        let opcode: AB::Expr = opcodes
            .iter()
            .zip(opcode_selectors.iter())
            .map(|(x, y)| x.clone() * *y)
            .sum();

        builder.receive_table(opcode, &operands, local_control_flow.is_syscall);

        let mut transition_builder = builder.when_transition();

        // Apply syscall constraints for compress.  Verify that the syscall parameters are copied to
        // the compress output row.
        {
            let mut compress_syscall_builder = transition_builder
                .when(local_control_flow.is_compress * local_control_flow.is_syscall);

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

        // Apply syscall constraints for absorb.  Verify that the syscall parameters are the same within
        // an absorb call.
        {
            let mut absorb_syscall_builder = transition_builder.when(local_control_flow.is_absorb);
            let mut absorb_syscall_builder =
                absorb_syscall_builder.when_not(next_control_flow.is_syscall);

            let local_syscall_params = local_syscall.absorb();
            let next_syscall_params = next_syscall.absorb();

            absorb_syscall_builder.assert_eq(local_syscall_params.clk, next_syscall_params.clk);
            absorb_syscall_builder
                .assert_eq(local_syscall_params.hash_num, next_syscall_params.hash_num);
            absorb_syscall_builder.assert_eq(
                local_syscall_params.input_ptr,
                next_syscall_params.input_ptr,
            );
            absorb_syscall_builder.assert_eq(local_syscall_params.len, next_syscall_params.len);
        }
    }
}
