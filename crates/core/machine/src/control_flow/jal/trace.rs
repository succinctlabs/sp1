use std::{borrow::BorrowMut, mem::MaybeUninit};

use hashbrown::HashMap;
use itertools::Itertools;
use slop_algebra::PrimeField32;
use slop_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ExecutionRecord, Program,
};
use sp1_hypercube::{air::MachineAir, Word};
use struct_reflection::StructReflectionHelper;

use crate::utils::next_multiple_of_32;

use super::{JalChip, JalColumns, NUM_JAL_COLS};

impl<F: PrimeField32> MachineAir<F> for JalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "Jal"
    }

    fn num_rows_for(&self, input: &Self::Record, apc_id: Option<usize>) -> Option<usize> {
        let nb_rows =
            next_multiple_of_32(input.jal_events_len(apc_id), input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let event_spans = input.jal_events_for(None);
        let jal_events: Vec<_> = event_spans.iter_events(&input.jal_events).collect();
        let chunk_size = std::cmp::max(jal_events.len() / num_cpus::get(), 1);

        let blu_batches = jal_events
            .chunks(chunk_size)
            .par_bridge()
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, isize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_JAL_COLS];
                    let cols: &mut JalColumns<F> = row.as_mut_slice().borrow_mut();

                    cols.is_real = F::one();
                    let low_limb = (event.0.pc.wrapping_add(event.0.b) & 0xFFFF) as u16;
                    blu.add_bit_range_check(low_limb / 4, 14);
                    cols.add_operation.populate(&mut blu, event.0.pc, event.0.b);
                    if !event.0.op_a_0 {
                        cols.op_a_operation.populate(&mut blu, event.0.pc, 4);
                    }
                    cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                    cols.adapter.populate(&mut blu, event.1);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn generate_trace_into_for(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
        apc_id: Option<usize>,
    ) {
        // Generate the rows for the trace.
        let event_spans = input.jal_events_for(apc_id);
        let jal_events: Vec<_> = event_spans.iter_events(&input.jal_events).collect();
        let chunk_size = std::cmp::max(jal_events.len() / num_cpus::get(), 1);
        let padded_nb_rows = <JalChip as MachineAir<F>>::num_rows_for(self, input, apc_id).unwrap();

        let num_event_rows = jal_events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_JAL_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_JAL_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_JAL_COLS) };

        values.chunks_mut(chunk_size * NUM_JAL_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                let mut blu = Vec::new();
                rows.chunks_mut(NUM_JAL_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    if idx < jal_events.len() {
                        let event = jal_events[idx];
                        let cols: &mut JalColumns<F> = row.borrow_mut();
                        cols.is_real = F::one();
                        cols.add_operation.populate(&mut blu, event.0.pc, event.0.b);
                        if !event.0.op_a_0 {
                            cols.op_a_operation.populate(&mut blu, event.0.pc, 4);
                        } else {
                            cols.op_a_operation.value = Word::from(0u64);
                        }
                        cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                        cols.adapter.populate(&mut blu, event.1);
                    }
                });
            },
        );
    }

    fn included_for(&self, shard: &Self::Record, apc_id: Option<usize>) -> bool {
        if apc_id.is_none() {
            if let Some(shape) = shard.shape.as_ref() {
                return shape.included::<F, _>(self);
            }
        }
        shard.jal_events_len(apc_id) > 0
    }

    fn column_names(&self) -> Vec<String> {
        JalColumns::<F>::struct_reflection().unwrap()
    }
}
