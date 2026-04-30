use std::{borrow::BorrowMut, mem::MaybeUninit};

use hashbrown::HashMap;
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use slop_air::BaseAir;
use slop_algebra::PrimeField32;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemoryRecordEnum, SyscallEvent},
    ExecutionRecord, Program, RTypeRecord, SyscallCode, HALT_PC,
};
use sp1_hypercube::{addr_to_limbs, air::MachineAir, Word};
use sp1_primitives::consts::u64_to_u16_limbs;
use struct_reflection::StructReflectionHelper;

use crate::{
    operations::SP1FieldWordRangeChecker, utils::next_multiple_of_32, TrustMode, UserMode,
    UserModeSyscallInstrCols,
};

use super::{columns::SyscallInstrColumns, SyscallInstrsChip};

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for SyscallInstrsChip<M> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "SyscallInstrs"
        } else {
            "SyscallInstrsUser"
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows = input.syscall_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }
        let chunk_size = std::cmp::max((input.syscall_events.len()) / num_cpus::get(), 1);
        let padded_nb_rows =
            <SyscallInstrsChip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let num_event_rows = input.syscall_events.len();
        let width = <SyscallInstrsChip<M> as BaseAir<F>>::width(self);

        unsafe {
            let padding_start = num_event_rows * width;
            let padding_size = (padded_nb_rows - num_event_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * width) };

        let blu_events = values
            .chunks_mut(chunk_size * width)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(width).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut SyscallInstrColumns<F, M> = row.borrow_mut();

                    if idx < input.syscall_events.len() {
                        let event = &input.syscall_events[idx];
                        self.event_to_row(&event.0, &event.1, cols, &mut blu);
                        cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                        cols.adapter.populate(&mut blu, event.1);
                        if !M::IS_TRUSTED {
                            let cols: &mut SyscallInstrColumns<F, UserMode> = row.borrow_mut();
                            cols.user_mode_cols = UserModeSyscallInstrCols::<F>::default();
                            let syscall_id = event.0.syscall_id;
                            cols.user_mode_cols.is_sig_return.populate_from_field_element(
                                F::from_canonical_u32(syscall_id)
                                    - F::from_canonical_u32(SyscallCode::SIG_RETURN.syscall_id()),
                            );
                            // Populate `is_page_protect`.
                            cols.user_mode_cols.is_page_protect.populate_from_field_element(
                                F::from_canonical_u32(syscall_id)
                                    - F::from_canonical_u32(SyscallCode::MPROTECT.syscall_id()),
                            );
                            #[cfg(feature = "mprotect")]
                            for i in 0..3 {
                                cols.user_mode_cols.addresses[i] =
                                    addr_to_limbs(input.public_values.trap_context[i]);
                            }
                            if let Some(pc_record) = event.0.sig_return_pc_record {
                                cols.user_mode_cols
                                    .next_pc_record
                                    .populate(MemoryRecordEnum::Read(pc_record), &mut blu);
                                let next_pc = pc_record.value;
                                cols.next_pc = addr_to_limbs::<F>(next_pc);
                            }
                            if let Some(trap_result) = event.0.trap_result {
                                cols.user_mode_cols.trap_operation.populate(&mut blu, trap_result);
                                let trap_code = trap_result.code_record.value;
                                cols.user_mode_cols.is_not_trap.populate(trap_code);
                                cols.user_mode_cols.trap_code = F::from_canonical_u64(trap_code);
                                let next_pc = trap_result.handler_record.value;
                                cols.next_pc = addr_to_limbs::<F>(next_pc);
                            } else {
                                cols.user_mode_cols.is_not_trap.populate(0);
                            }
                        }
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.syscall_events.is_empty()
                && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
        }
    }

    fn column_names(&self) -> Vec<String> {
        SyscallInstrColumns::<F, M>::struct_reflection().unwrap()
    }
}

impl<M: TrustMode> SyscallInstrsChip<M> {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &SyscallEvent,
        record: &RTypeRecord,
        cols: &mut SyscallInstrColumns<F, M>,
        blu: &mut impl ByteRecord,
    ) {
        cols.is_real = F::one();

        cols.op_a_value = Word::from(record.a.value());
        cols.a_low_bytes.populate_u16_to_u8_safe(blu, record.a.prev_value());
        blu.add_u16_range_checks(&u64_to_u16_limbs(record.a.value()));
        let a_prev_value = record.a.prev_value().to_le_bytes().map(F::from_canonical_u8);

        let syscall_id = a_prev_value[0];

        cols.is_halt =
            F::from_bool(syscall_id == F::from_canonical_u32(SyscallCode::HALT.syscall_id()));

        if cols.is_halt == F::one() {
            cols.next_pc = [F::from_canonical_u64(HALT_PC), F::zero(), F::zero()];
        } else {
            cols.next_pc = [
                F::from_canonical_u32(((event.pc & 0xFFFF) as u32) + 4),
                F::from_canonical_u32(((event.pc >> 16) & 0xFFFF) as u32),
                F::from_canonical_u32(((event.pc >> 32) & 0xFFFF) as u32),
            ];
        }

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

        cols.index_bitmap = [F::zero(); 8];
        cols.expected_public_values_digest = [F::zero(); 4];

        // For `COMMIT` or `COMMIT_DEFERRED_PROOFS`, set the index bitmap and digest word.
        if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT.syscall_id())
            || syscall_id == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
        {
            let digest_idx = record.b.value() as usize;
            cols.index_bitmap[digest_idx] = F::one();
        }

        // If the syscall is `COMMIT`, set the expected public values digest and range check.
        if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT.syscall_id()) {
            let digest_bytes = (record.c.value() as u32).to_le_bytes();
            cols.expected_public_values_digest = digest_bytes.map(F::from_canonical_u8);
            blu.add_u8_range_checks(&digest_bytes);
        }

        // Add the SP1Field range check of the operands.
        if cols.is_halt == F::one() {
            cols.op_b_range_check.populate(Word::from(event.arg1), blu);
        } else {
            cols.op_b_range_check = SP1FieldWordRangeChecker::default();
        }

        if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()) {
            cols.op_c_range_check.populate(Word::from(event.arg2), blu);
        } else {
            cols.op_c_range_check = SP1FieldWordRangeChecker::default();
        }
    }
}
