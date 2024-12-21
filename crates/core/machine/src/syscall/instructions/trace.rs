use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{ParallelBridge, ParallelIterator};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemoryRecordEnum, SyscallEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_stark::air::MachineAir;

use crate::utils::{next_power_of_two, zeroed_f_vec};

use super::{
    columns::{SyscallInstrColumns, NUM_SYSCALL_INSTR_COLS},
    SyscallInstrsChip,
};

impl<F: PrimeField32> MachineAir<F> for SyscallInstrsChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "SyscallInstrs".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.syscall_events.len()) / num_cpus::get(), 1);
        let nb_rows = input.syscall_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_SYSCALL_INSTR_COLS);

        let blu_events = values
            .chunks_mut(chunk_size * NUM_SYSCALL_INSTR_COLS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_SYSCALL_INSTR_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut SyscallInstrColumns<F> = row.borrow_mut();

                    if idx < input.syscall_events.len() {
                        let event = &input.syscall_events[idx];
                        self.event_to_row(event, cols, &mut blu);
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_SYSCALL_INSTR_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.syscall_events.is_empty()
        }
    }
}

impl SyscallInstrsChip {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &SyscallEvent,
        cols: &mut SyscallInstrColumns<F>,
        blu: &mut impl ByteRecord,
    ) {
        cols.is_real = F::one();
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);
        cols.shard = F::from_canonical_u32(event.shard);
        cols.clk = F::from_canonical_u32(event.clk);

        cols.op_a_access.populate(MemoryRecordEnum::Write(event.a_record), blu);
        cols.op_b_value = event.arg1.into();
        cols.op_c_value = event.arg2.into();

        let syscall_id = cols.op_a_access.prev_value[0];
        let num_cycles = cols.op_a_access.prev_value[2];

        cols.num_extra_cycles = num_cycles;
        cols.is_halt =
            F::from_bool(syscall_id == F::from_canonical_u32(SyscallCode::HALT.syscall_id()));

        // Populate `is_enter_unconstrained`.
        cols.is_enter_unconstrained.populate_from_field_element(
            syscall_id - F::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
        );

        // Populate `is_hint_len`.
        cols.is_hint_len.populate_from_field_element(
            syscall_id - F::from_canonical_u32(SyscallCode::HINT_LEN.syscall_id()),
        );

        // Populate `is_halt`.
        cols.is_halt_check.populate_from_field_element(
            syscall_id - F::from_canonical_u32(SyscallCode::HALT.syscall_id()),
        );

        // Populate `is_commit`.
        cols.is_commit.populate_from_field_element(
            syscall_id - F::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
        );

        // Populate `is_commit_deferred_proofs`.
        cols.is_commit_deferred_proofs.populate_from_field_element(
            syscall_id - F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()),
        );

        // If the syscall is `COMMIT` or `COMMIT_DEFERRED_PROOFS`, set the index bitmap and
        // digest word.
        if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT.syscall_id())
            || syscall_id == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
        {
            let digest_idx = cols.op_b_value.to_u32() as usize;
            cols.index_bitmap[digest_idx] = F::one();
        }

        // For halt and commit deferred proofs syscalls, we need to baby bear range check one of
        // it's operands.
        if cols.is_halt == F::one() {
            cols.operand_to_check = event.arg1.into();
            cols.operand_range_check_cols.populate(cols.operand_to_check, blu);
            cols.ecall_range_check_operand = F::one();
        }

        if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()) {
            cols.operand_to_check = event.arg2.into();
            cols.operand_range_check_cols.populate(cols.operand_to_check, blu);
            cols.ecall_range_check_operand = F::one();
        }
    }
}
