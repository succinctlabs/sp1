use p3_air::{Air, BaseAir};
use p3_matrix::Matrix;

use crate::air::SP1RecursionAirBuilder;

pub mod control_flow;
pub mod memory;
pub mod permutation;
pub mod state_transition;
pub mod syscall_params;

use super::{
    columns::{NUM_POSEIDON2_DEGREE3_COLS, NUM_POSEIDON2_DEGREE9_COLS},
    Poseidon2WideChip,
};

impl<F, const DEGREE: usize> BaseAir<F> for Poseidon2WideChip<DEGREE> {
    fn width(&self) -> usize {
        if DEGREE == 3 {
            NUM_POSEIDON2_DEGREE3_COLS
        } else if DEGREE == 9 {
            NUM_POSEIDON2_DEGREE9_COLS
        } else {
            panic!("Unsupported degree: {}", DEGREE);
        }
    }
}

impl<AB, const DEGREE: usize> Air<AB> for Poseidon2WideChip<DEGREE>
where
    AB: SP1RecursionAirBuilder,
    AB::Var: 'static,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = Self::convert::<AB::Var>(main.row_slice(0));
        let next_row = Self::convert::<AB::Var>(main.row_slice(1));
        let local_control_flow = local_row.control_flow();
        let next_control_flow = next_row.control_flow();
        let local_syscall = local_row.syscall_params();
        let next_syscall = next_row.syscall_params();
        let local_memory = local_row.memory();
        let next_memory = next_row.memory();
        let local_perm = local_row.permutation();
        let local_opcode_workspace = local_row.opcode_workspace();
        let next_opcode_workspace = next_row.opcode_workspace();

        // Check that all the control flow columns are correct.
        self.eval_control_flow(builder, local_row.as_ref(), next_row.as_ref());

        // Check that the syscall columns are correct.
        self.eval_syscall_params(
            builder,
            local_syscall,
            next_syscall,
            local_control_flow,
            next_control_flow,
        );

        // Check that all the memory access columns are correct.
        self.eval_mem(
            builder,
            local_syscall,
            local_memory,
            next_memory,
            local_opcode_workspace,
            local_control_flow,
        );

        // Check that the permutation columns are correct.
        self.eval_perm(
            builder,
            local_perm.as_ref(),
            local_memory,
            local_opcode_workspace,
            local_control_flow,
        );

        // Check that the permutation output is copied to the next row correctly.
        self.eval_state_transition(
            builder,
            local_control_flow,
            local_opcode_workspace,
            next_opcode_workspace,
            local_perm.as_ref(),
            local_memory,
            next_memory,
        );
    }
}
