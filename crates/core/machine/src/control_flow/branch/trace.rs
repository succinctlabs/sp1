use std::{borrow::BorrowMut, mem::MaybeUninit};

use hashbrown::HashMap;
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use slop_algebra::PrimeField32;
use sp1_core_executor::{
    events::{BranchEvent, ByteLookupEvent, ByteRecord},
    ExecutionRecord, Opcode, Program,
};
use sp1_hypercube::air::MachineAir;
use struct_reflection::StructReflectionHelper;

use crate::utils::next_multiple_of_32;

use super::{BranchChip, BranchColumns, NUM_BRANCH_COLS};

impl<F: PrimeField32> MachineAir<F> for BranchChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "Branch"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows =
            next_multiple_of_32(input.branch_events.len(), input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size = std::cmp::max((input.branch_events.len()) / num_cpus::get(), 1);

        let blu_batches = input
            .branch_events
            .chunks(chunk_size)
            .par_bridge()
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_BRANCH_COLS];
                    let cols: &mut BranchColumns<F> = row.as_mut_slice().borrow_mut();

                    self.event_to_row(&event.0, cols, &mut blu);
                    cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                    cols.adapter.populate(&mut blu, event.1);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        // Generate the rows for the trace.
        let chunk_size = std::cmp::max(input.branch_events.len() / num_cpus::get(), 1);
        let padded_nb_rows = <BranchChip as MachineAir<F>>::num_rows(self, input).unwrap();

        let num_event_rows = input.branch_events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_BRANCH_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_BRANCH_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_BRANCH_COLS)
        };

        values.chunks_mut(chunk_size * NUM_BRANCH_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                let mut blu = Vec::new();
                rows.chunks_mut(NUM_BRANCH_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut BranchColumns<F> = row.borrow_mut();

                    if idx < input.branch_events.len() {
                        let event = input.branch_events[idx];
                        self.event_to_row(&event.0, cols, &mut blu);
                        cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                        cols.adapter.populate(&mut blu, event.1);
                    }
                });
            },
        );
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.branch_events.is_empty()
        }
    }

    fn column_names(&self) -> Vec<String> {
        BranchColumns::<F>::struct_reflection().unwrap()
    }
}

impl BranchChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &BranchEvent,
        cols: &mut BranchColumns<F>,
        blu: &mut impl ByteRecord,
    ) {
        cols.is_beq = F::from_bool(matches!(event.opcode, Opcode::BEQ));
        cols.is_bne = F::from_bool(matches!(event.opcode, Opcode::BNE));
        cols.is_blt = F::from_bool(matches!(event.opcode, Opcode::BLT));
        cols.is_bge = F::from_bool(matches!(event.opcode, Opcode::BGE));
        cols.is_bltu = F::from_bool(matches!(event.opcode, Opcode::BLTU));
        cols.is_bgeu = F::from_bool(matches!(event.opcode, Opcode::BGEU));

        let a_eq_b = event.a == event.b;

        let use_signed_comparison = matches!(event.opcode, Opcode::BLT | Opcode::BGE);

        let a_lt_b = if use_signed_comparison {
            (event.a as i64) < (event.b as i64)
        } else {
            event.a < event.b
        };

        let branching = match event.opcode {
            Opcode::BEQ => a_eq_b,
            Opcode::BNE => !a_eq_b,
            Opcode::BLT | Opcode::BLTU => a_lt_b,
            Opcode::BGE | Opcode::BGEU => !a_lt_b,
            _ => unreachable!(),
        };

        cols.compare_operation.populate_signed(
            blu,
            a_lt_b as u64,
            event.a,
            event.b,
            use_signed_comparison,
        );

        cols.next_pc = [
            F::from_canonical_u16((event.next_pc & 0xFFFF) as u16),
            F::from_canonical_u16(((event.next_pc >> 16) & 0xFFFF) as u16),
            F::from_canonical_u16(((event.next_pc >> 32) & 0xFFFF) as u16),
        ];
        blu.add_bit_range_check((event.next_pc & 0xFFFF) as u16 / 4, 14);
        blu.add_u16_range_checks_field(&cols.next_pc[1..3]);

        if branching {
            cols.is_branching = F::one();
        } else {
            cols.is_branching = F::zero();
        }
    }
}
