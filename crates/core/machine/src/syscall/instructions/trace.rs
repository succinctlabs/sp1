use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use sp1_core_executor::{syscalls::SyscallCode, ExecutionRecord, Program};
use sp1_stark::air::MachineAir;

use super::SyscallInstrsChip;

impl<F: PrimeField32> MachineAir<F> for SyscallInstrsChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "SyscallInstrs".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut is_halt = false;

        if cols.selectors.is_ecall == F::one() {
            // The send_to_table column is the 1st entry of the op_a_access column prev_value field.
            // Look at `ecall_eval` in cpu/air/mod.rs for the corresponding constraint and
            // explanation.
            let ecall_cols = cols.opcode_specific_columns.ecall_mut();

            cols.ecall_mul_send_to_table = cols.selectors.is_ecall * cols.op_a_access.prev_value[1];

            let syscall_id = cols.op_a_access.prev_value[0];
            // let send_to_table = cols.op_a_access.prev_value[1];
            // let num_cycles = cols.op_a_access.prev_value[2];

            // Populate `is_enter_unconstrained`.
            ecall_cols.is_enter_unconstrained.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
            );

            // Populate `is_hint_len`.
            ecall_cols.is_hint_len.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::HINT_LEN.syscall_id()),
            );

            // Populate `is_halt`.
            ecall_cols.is_halt.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::HALT.syscall_id()),
            );

            // Populate `is_commit`.
            ecall_cols.is_commit.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
            );

            // Populate `is_commit_deferred_proofs`.
            ecall_cols.is_commit_deferred_proofs.populate_from_field_element(
                syscall_id
                    - F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()),
            );

            // If the syscall is `COMMIT` or `COMMIT_DEFERRED_PROOFS`, set the index bitmap and
            // digest word.
            if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT.syscall_id())
                || syscall_id
                    == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
            {
                let digest_idx = cols.op_b_access.value().to_u32() as usize;
                ecall_cols.index_bitmap[digest_idx] = F::one();
            }

            // Write the syscall nonce.
            ecall_cols.syscall_nonce =
                F::from_canonical_u32(nonce_lookup[event.syscall_lookup_id.0 as usize]);

            is_halt = syscall_id == F::from_canonical_u32(SyscallCode::HALT.syscall_id());

            // For halt and commit deferred proofs syscalls, we need to baby bear range check one of
            // it's operands.
            if is_halt {
                ecall_cols.operand_to_check = event.b.into();
                ecall_cols.operand_range_check_cols.populate(event.b);
                cols.ecall_range_check_operand = F::one();
            }

            if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
            {
                ecall_cols.operand_to_check = event.c.into();
                ecall_cols.operand_range_check_cols.populate(event.c);
                cols.ecall_range_check_operand = F::one();
            }
        }

        is_halt
    }
}
