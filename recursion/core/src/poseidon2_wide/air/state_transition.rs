use std::array;

use p3_air::AirBuilder;
use sp1_core::air::BaseAirBuilder;

use crate::{
    air::SP1RecursionAirBuilder,
    memory::MemoryCols,
    poseidon2_wide::{
        columns::{
            control_flow::ControlFlow, memory::Memory, opcode_workspace::OpcodeWorkspace,
            permutation::Permutation,
        },
        Poseidon2WideChip, WIDTH,
    },
};

impl<const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn eval_state_transition<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        control_flow: &ControlFlow<AB::Var>,
        local_opcode_workspace: &OpcodeWorkspace<AB::Var>,
        next_opcode_workspace: &OpcodeWorkspace<AB::Var>,
        permutation: &dyn Permutation<AB::Var>,
        local_memory: &Memory<AB::Var>,
        next_memory: &Memory<AB::Var>,
    ) {
        // For compress syscall rows, contrain that the permutation's output is equal to the compress
        // output's memory values.
        {
            let next_memory_output: [AB::Var; WIDTH] = array::from_fn(|i| {
                if i < WIDTH / 2 {
                    *next_memory.memory_accesses[i].value()
                } else {
                    *next_opcode_workspace.compress().memory_accesses[i - WIDTH / 2].value()
                }
            });

            builder
                .when_transition()
                .when(control_flow.is_compress)
                .when(control_flow.is_syscall_row)
                .assert_all_eq(next_memory_output, *permutation.perm_output());
        }

        // Absorb
        {
            // Expected state when a permutation is done.
            builder
                .when(control_flow.is_absorb)
                .when(local_opcode_workspace.absorb().do_perm::<AB>())
                .assert_all_eq(
                    local_opcode_workspace.absorb().state,
                    *permutation.perm_output(),
                );

            // TODO: move the permutation input as a method for the poseidon2 struct.
            let input: [AB::Expr; WIDTH] = array::from_fn(|i| {
                if i < WIDTH / 2 {
                    builder.if_else(
                        local_memory.memory_slot_used[i],
                        *local_memory.memory_accesses[i].value(),
                        local_opcode_workspace.absorb().previous_state[i],
                    )
                } else {
                    local_opcode_workspace.absorb().previous_state[i].into()
                }
            });

            builder
                .when(control_flow.is_absorb_no_perm)
                .assert_all_eq(local_opcode_workspace.absorb().state, input);

            builder
                .when_transition()
                .when(control_flow.is_absorb)
                .assert_all_eq(
                    local_opcode_workspace.absorb().state,
                    next_opcode_workspace.absorb().previous_state,
                );
        }

        // Finalize
        {
            builder
                .when(control_flow.is_finalize)
                .when(local_opcode_workspace.finalize().do_perm::<AB>())
                .assert_all_eq(
                    local_opcode_workspace.finalize().state,
                    *permutation.perm_output(),
                );

            builder
                .when(control_flow.is_finalize)
                .when_not(local_opcode_workspace.finalize().do_perm::<AB>())
                .assert_all_eq(
                    local_opcode_workspace.finalize().state,
                    local_opcode_workspace.finalize().previous_state,
                );
        }
    }
}
