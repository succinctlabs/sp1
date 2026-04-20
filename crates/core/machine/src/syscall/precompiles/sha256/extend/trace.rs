use hashbrown::HashMap;
use itertools::Itertools;
use slop_algebra::PrimeField32;
use slop_maybe_rayon::prelude::{
    IndexedParallelIterator, ParallelIterator, ParallelSlice, ParallelSliceMut,
};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemoryRecordEnum, PrecompileEvent, ShaExtendEvent},
    ByteOpcode, ExecutionRecord, Program, SyscallCode, TrapError,
};
use sp1_hypercube::air::MachineAir;
use std::{borrow::BorrowMut, mem::MaybeUninit};

use crate::utils::next_multiple_of_32;

use super::{ShaExtendChip, ShaExtendCols, NUM_SHA_EXTEND_COLS};

impl<F: PrimeField32> MachineAir<F> for ShaExtendChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "ShaExtend"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        // Each extend syscall takes 48 rows.
        let nb_rows = input.get_precompile_events(SyscallCode::SHA_EXTEND).len() * 48;
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let padded_nb_rows = <ShaExtendChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = input.get_precompile_events(SyscallCode::SHA_EXTEND);

        let num_event_rows = events.len() * 48;

        unsafe {
            let padding_start = num_event_rows * NUM_SHA_EXTEND_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_SHA_EXTEND_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_SHA_EXTEND_COLS)
        };

        values.par_chunks_mut(NUM_SHA_EXTEND_COLS * 48).enumerate().for_each(|(idx, row)| {
            let mut blu = Vec::new();
            let event = &events[idx].1;
            let event =
                if let PrecompileEvent::ShaExtend(event) = event { event } else { unreachable!() };
            unsafe {
                core::ptr::write_bytes(row.as_mut_ptr(), 0, NUM_SHA_EXTEND_COLS * 48);
            }
            self.event_to_rows(event, &events[idx].0.trap_error, row, &mut blu);
        });
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = input.get_precompile_events(SyscallCode::SHA_EXTEND);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                let mut row = vec![F::zero(); NUM_SHA_EXTEND_COLS * 48];
                events.iter().for_each(|(syscall_event, event)| {
                    let event = if let PrecompileEvent::ShaExtend(event) = event {
                        event
                    } else {
                        unreachable!()
                    };
                    self.event_to_rows::<F>(event, &syscall_event.trap_error, &mut row, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::SHA_EXTEND).is_empty()
        }
    }
}

impl ShaExtendChip {
    fn event_to_rows<F: PrimeField32>(
        &self,
        event: &ShaExtendEvent,
        trap_error: &Option<TrapError>,
        rows: &mut [F],
        blu: &mut impl ByteRecord,
    ) {
        if trap_error.is_some() {
            return;
        }

        // Extend now begins one cycle after the actual syscall itself, therefore need to use
        // a bumped clk.
        let bumped_clk = event.clk + 1;
        for j in 0..48usize {
            let start = j * NUM_SHA_EXTEND_COLS;
            let end = (j + 1) * NUM_SHA_EXTEND_COLS;
            let cols: &mut ShaExtendCols<F> = rows[start..end].borrow_mut();
            cols.is_real = F::one();
            let i = j as u64 + 16;
            cols.i = F::from_canonical_u64(i);
            cols.clk_high = F::from_canonical_u32((bumped_clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((bumped_clk & 0xFFFFFF) as u32);
            cols.next_clk.populate(blu, bumped_clk, j as u64);
            cols.w_ptr = [
                F::from_canonical_u64((event.w_ptr & 0xFFFF) as u64),
                F::from_canonical_u64(((event.w_ptr >> 16) & 0xFFFF) as u64),
                F::from_canonical_u64(((event.w_ptr >> 32) & 0xFFFF) as u64),
            ];
            cols.w_i_minus_15_ptr.populate(blu, event.w_ptr, (i - 15) * 8);
            cols.w_i_minus_2_ptr.populate(blu, event.w_ptr, (i - 2) * 8);
            cols.w_i_minus_16_ptr.populate(blu, event.w_ptr, (i - 16) * 8);
            cols.w_i_minus_7_ptr.populate(blu, event.w_ptr, (i - 7) * 8);
            cols.w_i_ptr.populate(blu, event.w_ptr, i * 8);

            let w_i_minus_15_read =
                MemoryRecordEnum::Read(event.memory_records[j].w_i_minus_15_reads);
            let w_i_minus_2_read =
                MemoryRecordEnum::Read(event.memory_records[j].w_i_minus_2_reads);
            let w_i_minus_16_read =
                MemoryRecordEnum::Read(event.memory_records[j].w_i_minus_16_reads);
            let w_i_minus_7_read =
                MemoryRecordEnum::Read(event.memory_records[j].w_i_minus_7_reads);

            cols.w_i_minus_15.populate(w_i_minus_15_read, blu);
            cols.w_i_minus_2.populate(w_i_minus_2_read, blu);
            cols.w_i_minus_16.populate(w_i_minus_16_read, blu);
            cols.w_i_minus_7.populate(w_i_minus_7_read, blu);

            // `s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift
            // 3)`.
            let w_i_minus_15 = event.memory_records[j].w_i_minus_15_reads.value;
            let w_i_minus_15_rr_7 = cols.w_i_minus_15_rr_7.populate(blu, w_i_minus_15 as u32, 7);
            let w_i_minus_15_rr_18 = cols.w_i_minus_15_rr_18.populate(blu, w_i_minus_15 as u32, 18);
            let w_i_minus_15_rs_3 = cols.w_i_minus_15_rs_3.populate(blu, w_i_minus_15 as u32, 3);
            let s0_intermediate = cols.s0_intermediate.populate_xor_u32(
                blu,
                w_i_minus_15_rr_7 as u32,
                w_i_minus_15_rr_18 as u32,
            );
            let s0 = cols.s0.populate_xor_u32(blu, s0_intermediate, w_i_minus_15_rs_3);

            // `s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift
            // 10)`.
            let w_i_minus_2 = event.memory_records[j].w_i_minus_2_reads.value;
            let w_i_minus_2_rr_17 = cols.w_i_minus_2_rr_17.populate(blu, w_i_minus_2 as u32, 17);
            let w_i_minus_2_rr_19 = cols.w_i_minus_2_rr_19.populate(blu, w_i_minus_2 as u32, 19);
            let w_i_minus_2_rs_10 = cols.w_i_minus_2_rs_10.populate(blu, w_i_minus_2 as u32, 10);
            let s1_intermediate =
                cols.s1_intermediate.populate_xor_u32(blu, w_i_minus_2_rr_17, w_i_minus_2_rr_19);
            let s1 = cols.s1.populate_xor_u32(blu, s1_intermediate, w_i_minus_2_rs_10);

            // Compute `s2`.
            let w_i_minus_7 = event.memory_records[j].w_i_minus_7_reads.value;
            let w_i_minus_16 = event.memory_records[j].w_i_minus_16_reads.value;
            cols.s2.populate(blu, w_i_minus_16 as u32, s0, w_i_minus_7 as u32, s1);

            let w_i_write = MemoryRecordEnum::Write(event.memory_records[j].w_i_write);
            cols.w_i.populate(w_i_write, blu);
            blu.add_byte_lookup_event(ByteLookupEvent {
                opcode: ByteOpcode::LTU,
                a: 1u16,
                b: j as u8,
                c: 48,
            });
        }
    }
}
