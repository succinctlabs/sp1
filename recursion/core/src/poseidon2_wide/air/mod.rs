use p3_air::{Air, BaseAir};
use p3_matrix::Matrix;

use crate::air::SP1RecursionAirBuilder;

pub mod control_flow;
pub mod memory;
pub mod permutation;
pub mod state_transition;
pub mod syscall_params;

use super::{
    columns::{Poseidon2, NUM_POSEIDON2_DEGREE3_COLS, NUM_POSEIDON2_DEGREE9_COLS},
    Poseidon2WideChip, WIDTH,
};

impl<F, const DEGREE: usize, const ROUND_CHUNK_SIZE: usize> BaseAir<F>
    for Poseidon2WideChip<DEGREE, ROUND_CHUNK_SIZE>
{
    fn width(&self) -> usize {
        if DEGREE == 3 {
            NUM_POSEIDON2_DEGREE3_COLS
        } else if DEGREE == 9 || DEGREE == 17 {
            NUM_POSEIDON2_DEGREE9_COLS
        } else {
            panic!("Unsupported degree: {}", DEGREE);
        }
    }
}

impl<AB, const DEGREE: usize, const ROUND_CHUNK_SIZE: usize> Air<AB>
    for Poseidon2WideChip<DEGREE, ROUND_CHUNK_SIZE>
where
    AB: SP1RecursionAirBuilder,
    AB::Var: 'static,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_row = Self::convert::<AB::Var>(main.row_slice(0));
        let next_row = Self::convert::<AB::Var>(main.row_slice(1));

        // Dummy constraints to normalize to DEGREE.
        let lhs = (0..DEGREE)
            .map(|_| local_row.control_flow().is_compress.into())
            .product::<AB::Expr>();
        let rhs = (0..DEGREE)
            .map(|_| local_row.control_flow().is_compress.into())
            .product::<AB::Expr>();
        builder.assert_eq(lhs, rhs);

        self.eval_poseidon2(
            builder,
            local_row.as_ref(),
            next_row.as_ref(),
            local_row.control_flow().is_syscall_row,
            local_row.memory().memory_slot_used,
            local_row.control_flow().is_compress,
        );
    }
}

impl<const DEGREE: usize, const ROUND_CHUNK_SIZE: usize>
    Poseidon2WideChip<DEGREE, ROUND_CHUNK_SIZE>
{
    pub(crate) fn eval_poseidon2<AB>(
        &self,
        builder: &mut AB,
        local_row: &dyn Poseidon2<AB::Var>,
        next_row: &dyn Poseidon2<AB::Var>,
        receive_syscall: AB::Var,
        first_half_memory_access: [AB::Var; WIDTH / 2],
        second_half_memory_access: AB::Var,
    ) where
        AB: SP1RecursionAirBuilder,
        AB::Var: 'static,
    {
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
        self.eval_control_flow(builder, local_row, next_row);

        // Check that the syscall columns are correct.
        self.eval_syscall_params(
            builder,
            local_syscall,
            next_syscall,
            local_control_flow,
            next_control_flow,
            receive_syscall,
        );

        // Check that all the memory access columns are correct.
        self.eval_mem(
            builder,
            local_syscall,
            local_memory,
            next_memory,
            local_opcode_workspace,
            local_control_flow,
            first_half_memory_access,
            second_half_memory_access,
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
