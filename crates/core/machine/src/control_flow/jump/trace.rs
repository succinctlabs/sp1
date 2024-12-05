use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{ParallelBridge, ParallelIterator};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, JumpEvent},
    ExecutionRecord, Opcode, Program,
};
use sp1_stark::air::MachineAir;

use crate::utils::{next_power_of_two, zeroed_f_vec};

use super::{JumpChip, JumpColumns, NUM_JUMP_COLS};

impl<F: PrimeField32> MachineAir<F> for JumpChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Jump".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.jump_events.len()) / num_cpus::get(), 1);
        let nb_rows = input.jump_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_JUMP_COLS);

        let blu_events = values
            .chunks_mut(chunk_size * NUM_JUMP_COLS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_JUMP_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut JumpColumns<F> = row.borrow_mut();

                    if idx < input.jump_events.len() {
                        let event = &input.jump_events[idx];
                        self.event_to_row(event, cols, &mut blu);
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_JUMP_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.jump_events.is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl JumpChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &JumpEvent,
        cols: &mut JumpColumns<F>,
        blu: &mut HashMap<ByteLookupEvent, usize>,
    ) {
        cols.is_jal = F::from_bool(matches!(event.opcode, Opcode::JAL));
        cols.is_jalr = F::from_bool(matches!(event.opcode, Opcode::JALR));

        cols.op_a_value = event.a.into();
        cols.op_b_value = event.b.into();
        cols.op_c_value = event.c.into();
        cols.op_a_0 = F::from_bool(event.op_a_0);

        cols.op_a_range_checker.populate(cols.op_a_value, blu);

        cols.pc = event.pc.into();
        cols.pc_range_checker.populate(cols.pc, blu);

        let next_pc = match event.opcode {
            Opcode::JAL => event.pc.wrapping_add(event.b),
            Opcode::JALR => event.b.wrapping_add(event.c),
            _ => unreachable!(),
        };

        cols.next_pc = next_pc.into();
        cols.next_pc_range_checker.populate(cols.next_pc, blu);
    }
}
