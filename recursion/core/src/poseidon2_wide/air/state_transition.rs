use std::array;

use p3_air::AirBuilder;
use sp1_core::{air::BaseAirBuilder, utils::DIGEST_SIZE};

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
        // For compress syscall rows, verify that the permutation output's state is equal to
        // the compress output memory values.
        {
            let compress_output_mem_values: [AB::Var; WIDTH] = array::from_fn(|i| {
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
                .assert_all_eq(compress_output_mem_values, *permutation.perm_output());
        }

        // Absorb rows.
        {
            // Check that the state is zero on the first_hash_row.
            builder
                .when(control_flow.is_absorb)
                .when(local_opcode_workspace.absorb().is_first_hash_row)
                .assert_all_zero(local_opcode_workspace.absorb().previous_state);

            // Check that the state is equal to the permutation output when the permutation is applied.
            builder
                .when(control_flow.is_absorb)
                .when(local_opcode_workspace.absorb().do_perm::<AB>())
                .assert_all_eq(
                    local_opcode_workspace.absorb().state,
                    *permutation.perm_output(),
                );

            // Construct the input into the permutation.
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

            // Check that the state is equal the the permutation input when the permutation is not applied.
            builder
                .when(control_flow.is_absorb_no_perm)
                .assert_all_eq(local_opcode_workspace.absorb().state, input);

            // Check that the state is copied to the next row.
            builder
                .when_transition()
                .when(control_flow.is_absorb)
                .assert_all_eq(
                    local_opcode_workspace.absorb().state,
                    next_opcode_workspace.absorb().previous_state,
                );
        }

        // Finalize rows.
        {
            // Check that the state is equal to the permutation output when the permutation is applied.
            builder
                .when(control_flow.is_finalize)
                .when(local_opcode_workspace.finalize().do_perm::<AB>())
                .assert_all_eq(
                    local_opcode_workspace.finalize().state,
                    *permutation.perm_output(),
                );

            // Check that the state is equal to the previous state when the permutation is not applied.
            builder
                .when(control_flow.is_finalize)
                .when_not(local_opcode_workspace.finalize().do_perm::<AB>())
                .assert_all_eq(
                    local_opcode_workspace.finalize().state,
                    local_opcode_workspace.finalize().previous_state,
                );

            // Check that the finalize memory values are equal to the state.
            let output_mem_values: [AB::Var; DIGEST_SIZE] =
                array::from_fn(|i| *local_memory.memory_accesses[i].value());

            builder.when(control_flow.is_finalize).assert_all_eq(
                output_mem_values,
                local_opcode_workspace.finalize().state[0..DIGEST_SIZE].to_vec(),
            );
        }
    }
}
