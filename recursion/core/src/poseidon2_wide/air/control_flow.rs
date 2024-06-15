use p3_air::AirBuilder;
use p3_field::AbstractField;
use sp1_core::air::BaseAirBuilder;

use crate::{
    air::SP1RecursionAirBuilder,
    poseidon2_wide::{
        columns::{
            control_flow::ControlFlow, opcode_workspace::OpcodeWorkspace,
            syscall_params::SyscallParams, Poseidon2,
        },
        Poseidon2WideChip,
    },
};

impl<const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    pub(crate) fn eval_control_flow<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local_row: &dyn Poseidon2<AB::Var>,
        next_row: &dyn Poseidon2<AB::Var>,
    ) where
        AB::Var: 'static,
    {
        let local_control_flow = local_row.control_flow();
        let next_control_flow = next_row.control_flow();
        let local_syscall_params = local_row.syscall_params();
        let next_syscall_params = next_row.syscall_params();
        let local_opcode_workspace = local_row.opcode_workspace();
        let next_opcode_workspace = next_row.opcode_workspace();

        let local_is_real = local_control_flow.is_compress
            + local_control_flow.is_absorb
            + local_control_flow.is_finalize;
        let next_is_real = next_control_flow.is_compress
            + next_control_flow.is_absorb
            + next_control_flow.is_finalize;

        builder.assert_bool(local_control_flow.is_compress);
        builder.assert_bool(local_control_flow.is_compress_output);
        builder.assert_bool(local_control_flow.is_absorb);
        builder.assert_bool(local_control_flow.is_finalize);
        builder.assert_bool(local_is_real.clone());

        builder.assert_bool(local_control_flow.is_syscall);
        builder.assert_bool(local_control_flow.do_perm);

        self.global_control_flow(
            builder,
            local_control_flow,
            next_control_flow,
            local_syscall_params,
            next_syscall_params,
            local_opcode_workspace,
            next_opcode_workspace,
            local_is_real.clone(),
            next_is_real.clone(),
        );

        // Apply control flow constraints for absorb.
        {
            let mut absorb_builder = builder.when(local_control_flow.is_absorb);

            // Verify the is_absorb_no_perm flag.
            absorb_builder.assert_eq(
                local_control_flow.is_absorb_no_perm,
                local_control_flow.is_absorb * (AB::Expr::one() - local_control_flow.do_perm),
            );

            // Every row right after the absorb syscall must either be an absorb or finalize.
            absorb_builder
                .when_transition()
                .assert_one(next_control_flow.is_absorb + next_control_flow.is_finalize);
        }

        // Apply control flow constraints for finalize.
        {
            let mut finalize_builder = builder.when(local_control_flow.is_finalize);

            // Every finalize row must be a syscall, not an input, an output, and not a permutation.
            finalize_builder.assert_one(local_control_flow.is_syscall);

            // Every next real row after finalize must be either a compress or absorb and must be a syscall.
            finalize_builder
                .when_transition()
                .when(next_is_real.clone())
                .assert_one(next_control_flow.is_compress + next_control_flow.is_absorb);
            finalize_builder
                .when_transition()
                .when(next_is_real.clone())
                .assert_one(next_control_flow.is_syscall);
        }

        // Apply control flow contraints for compress syscall.
        self.eval_compress_control_flow(
            builder,
            local_control_flow,
            next_control_flow,
            next_is_real,
        );
    }

    /// This function will verify that all hash rows (absorb and finalize) are before the compress rows
    /// and that the first row is the first absorb syscall.
    /// We assume that there are at least one absorb, finalize, and compress invocations.
    #[allow(clippy::too_many_arguments)]
    fn global_control_flow<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local_control_flow: &ControlFlow<AB::Var>,
        next_control_flow: &ControlFlow<AB::Var>,
        local_syscall_params: &SyscallParams<AB::Var>,
        next_syscall_params: &SyscallParams<AB::Var>,
        local_opcode_workspace: &OpcodeWorkspace<AB::Var>,
        next_opcode_workspace: &OpcodeWorkspace<AB::Var>,
        local_is_real: AB::Expr,
        next_is_real: AB::Expr,
    ) {
        // We require that the first row is an absorb syscall and that the hash_num == 0.
        let mut first_row_builder = builder.when_first_row();
        first_row_builder.assert_one(local_control_flow.is_absorb);
        first_row_builder.assert_one(local_control_flow.is_syscall);
        first_row_builder.assert_zero(local_syscall_params.absorb().hash_num);
        first_row_builder.assert_one(local_opcode_workspace.hash().is_first_hash_row);

        let mut transition_builder = builder.when_transition();

        // All rows from a hash invocation should be grouped together with the same hash_num.  To
        // enforce that, the following constraints are enforced.

        // 1) If absorb row -> next row is absorb or finalize.
        // 2) If absorb row -> hash_num == hash_num'.
        // 3) If finalize row -> next row is compress or finalize row.
        // 4) If finalize row and next row is absorb ->
        //          hash_num + 1 == hash_num'
        //      AND is_first_hash' == 1
        // 5) If finalize row and next row is compress -> is compress syscall
        let mut absorb_transition_builder = transition_builder.when(local_control_flow.is_absorb);
        absorb_transition_builder
            .assert_one(next_control_flow.is_absorb + next_control_flow.is_finalize);
        absorb_transition_builder
            .when(next_control_flow.is_absorb)
            .assert_eq(
                local_syscall_params.absorb().hash_num,
                next_syscall_params.absorb().hash_num,
            );
        absorb_transition_builder
            .when(next_control_flow.is_finalize)
            .assert_eq(
                local_syscall_params.absorb().hash_num,
                next_syscall_params.finalize().hash_num,
            );

        let mut finalize_transition_builder =
            transition_builder.when(local_control_flow.is_finalize);

        finalize_transition_builder
            .assert_one(next_control_flow.is_absorb + next_control_flow.is_compress);
        finalize_transition_builder
            .when(next_control_flow.is_absorb)
            .assert_eq(
                local_syscall_params.finalize().hash_num + AB::Expr::one(),
                next_syscall_params.absorb().hash_num,
            );
        finalize_transition_builder
            .when(next_control_flow.is_absorb)
            .assert_one(next_opcode_workspace.hash().is_first_hash_row);
        finalize_transition_builder
            .when(next_control_flow.is_compress)
            .assert_one(next_control_flow.is_syscall);

        // If compress row -> next row is compress or not real.
        transition_builder
            .when(local_control_flow.is_compress)
            .assert_one(next_control_flow.is_compress + (AB::Expr::one() - next_is_real.clone()));

        // If row is not real -> next row is not real.
        transition_builder
            .when_not(local_is_real.clone())
            .assert_zero(next_is_real);

        // If the last row is real -> is a compress output row.
        builder
            .when_last_row()
            .when(local_is_real)
            .assert_one(local_control_flow.is_compress_output);
    }

    fn eval_compress_control_flow<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local_control_flow: &ControlFlow<AB::Var>,
        next_control_flow: &ControlFlow<AB::Var>,
        next_is_real: AB::Expr,
    ) {
        // Compress syscall control flow contraints.
        {
            let mut compress_syscall_builder =
                builder.when(local_control_flow.is_compress * local_control_flow.is_syscall);

            // Every compress syscall row must do a permutation.
            compress_syscall_builder.assert_one(local_control_flow.do_perm);

            // Row right after the compress syscall must be a compress output.
            compress_syscall_builder
                .when_transition()
                .assert_one(next_control_flow.is_compress_output);
        }

        // Compress output control flow constraints.
        {
            let mut compress_output_builder = builder.when(local_control_flow.is_compress_output);
            compress_output_builder.assert_zero(local_control_flow.is_syscall);
            compress_output_builder.assert_zero(local_control_flow.do_perm);
            compress_output_builder
                .when_transition()
                .when(next_is_real)
                .assert_one(next_control_flow.is_compress * next_control_flow.is_syscall);
        }
    }
}
