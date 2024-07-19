//! The air module contains the AIR constraints for the poseidon2 chip.  Those constraints will
//! enforce the following properties:
//!
//! # Layout of the poseidon2 chip:
//!
//! All the hash related rows should be in the first part of the chip and all the compress
//! related rows in the second part.  E.g. the chip should have this format:
//!
//! absorb row (for hash num 1)
//! absorb row (for hash num 1)
//! absorb row (for hash num 1)
//! finalize row (for hash num 1)
//! absorb row (for hash num 2)
//! absorb row (for hash num 2)
//! finalize row (for hash num 2)
//! .
//! .
//! .
//! compress syscall/input row
//! compress output row
//!
//! # Absorb rows
//!
//! For absorb rows, the AIR needs to ensure that all of the input is written into the hash state
//! and that its written into the correct parts of that state.  To do this, the AIR will first ensure
//! the correct values for num_remaining_rows (e.g. total number of rows of an absorb syscall) and
//! the last_row_ending_cursor.  It does this by checking the following:
//!
//! 1. start_state_cursor + syscall_input_len == num_remaining_rows * RATE + last_row_ending_cursor
//! 2. range check syscall_input_len to be [0, 2^16 - 1]
//! 3. range check last_row_ending_cursor to be [0, RATE]
//!
//! For all subsequent absorb rows, the num_remaining_rows will be decremented by 1, and the
//! last_row_ending_cursor will be copied down to all of the rows.  Also, for the next absorb/finalize
//! syscall, its state_cursor is set to (last_row_ending_cursor + 1) % RATE.
//!
//! From num_remaining_rows and syscall column, we know the absorb's first row and last row.
//! From that fact, we can then enforce the following state writes.
//!
//! 1. is_first_row && is_last_row -> state writes are [state_cursor..state_cursor + last_row_ending_cursor]
//! 2. is_first_row && !is_last_row -> state writes are [state_cursor..RATE - 1]
//! 3. !is_first_row && !is_last_row -> state writes are [0..RATE - 1]
//! 4. !is_first_row && is_last_row -> state writes are [0..last_row_ending_cursor]
//!
//! From the state writes range, we can then populate a bitmap that specifies which state elements
//! should be overwritten (stored in Memory.memory_slot_used columns).  To verify that this bitmap
//! is correct, we utilize the column's derivative (memory_slot_used[i] - memory_slot_used[i-1],
//! where memory_slot_used[-1] is 0).
//!
//! 1. When idx == state write start_idx -> derivative == 1
//! 2. When idx == (state write end_idx - 1) -> derivative == -1
//! 3. For all other cases, derivative == 0
//!
//! In addition to determining the hash state writes, the AIR also needs to ensure that the do_perm
//! flag is correct (which is used to determine if a permutation should be done).  It does this
//! by enforcing the following.
//!
//! 1. is_first_row && !is_last_row -> do_perm == 1
//! 2. !is_first_row && !is_last_row -> do_perm == 1
//! 3. is_last_row && last_row_ending_cursor == RATE - 1 -> do_perm == 1
//! 4. is_last_row && last_row_ending_cursor != RATE - 1 -> do_perm == 0
//!
//! # Finalize rows
//!
//! For finalize, the main flag that needs to be checked is do_perm.  If state_cursor == 0, then
//! do_perm should be 0, otherwise it should be 1.  If state_cursor == 0, that means that the
//! previous row did a perm.
//!
//! # Compress rows
//!
//! For compress, the main invariants that needs to be checked is that all syscall compress rows
//! verifies the correct memory read accesses, does the permutation, and copies the permuted value
//! into the next row.  That row should then verify the correct memory write accesses.

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

impl<F, const DEGREE: usize> BaseAir<F> for Poseidon2WideChip<DEGREE> {
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

impl<AB, const DEGREE: usize> Air<AB> for Poseidon2WideChip<DEGREE>
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
            local_row.control_flow().is_absorb,
        );
    }
}

impl<const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn eval_poseidon2<AB>(
        &self,
        builder: &mut AB,
        local_row: &dyn Poseidon2<AB::Var>,
        next_row: &dyn Poseidon2<AB::Var>,
        receive_syscall: AB::Var,
        first_half_memory_access: [AB::Var; WIDTH / 2],
        second_half_memory_access: AB::Var,
        send_range_check: AB::Var,
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
        self.eval_control_flow(builder, local_row, next_row, send_range_check);

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
