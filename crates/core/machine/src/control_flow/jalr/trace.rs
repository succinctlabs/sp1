use std::{borrow::BorrowMut, mem::MaybeUninit};

use hashbrown::HashMap;
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use slop_algebra::PrimeField32;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, JumpEvent},
    ExecutionRecord, Program,
};
use sp1_hypercube::{air::MachineAir, Word};
use struct_reflection::StructReflectionHelper;

use crate::utils::next_multiple_of_32;

use super::{JalrChip, JalrColumns, NUM_JALR_COLS};

impl<F: PrimeField32> MachineAir<F> for JalrChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "Jalr"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows =
            next_multiple_of_32(input.jalr_events.len(), input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let chunk_size = std::cmp::max((input.jalr_events.len()) / num_cpus::get(), 1);
        let padded_nb_rows = <JalrChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let num_event_rows = input.jalr_events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_JALR_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_JALR_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * NUM_JALR_COLS) };

        let blu_events = values
            .chunks_mut(chunk_size * NUM_JALR_COLS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_JALR_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut JalrColumns<F> = row.borrow_mut();

                    if idx < input.jalr_events.len() {
                        let event = &input.jalr_events[idx];
                        self.event_to_row(&event.0, event.1.op_c, cols, &mut blu);
                        cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                        cols.adapter.populate(&mut blu, event.1);
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
            !shard.jalr_events.is_empty()
        }
    }

    fn column_names(&self) -> Vec<String> {
        JalrColumns::<F>::struct_reflection().unwrap()
    }
}

impl JalrChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &JumpEvent,
        imm: u64,
        cols: &mut JalrColumns<F>,
        blu: &mut HashMap<ByteLookupEvent, usize>,
    ) {
        cols.is_real = F::one();
        let low_limb = (event.b.wrapping_add(imm) & 0xFFFF) as u16;
        blu.add_bit_range_check(low_limb / 4, 14);
        cols.lsb = F::from_canonical_u16(low_limb & 1);
        cols.add_operation.populate(blu, event.b, imm);
        if !event.op_a_0 {
            cols.op_a_operation.populate(blu, event.pc, 4);
        } else {
            cols.op_a_operation.value = Word::from(0u64);
        }
    }
}
