use std::borrow::BorrowMut;

use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    air::Word,
    memory::{MemoryCols, MemoryReadWriteCols},
    runtime::Segment,
    utils::{ec::NUM_WORDS_FIELD_ELEMENT, Chip},
};

use super::{
    columns::{
        Poseidon2ExternalCols, NUM_POSEIDON2_EXTERNAL_COLS, POSEIDON2_DEFAULT_EXTERNAL_ROUNDS,
    },
    Poseidon2ExternalChip,
};

// I just copied and pasted these from sha compress as a starting point. Carefully examine the code
// and update it. Most computation doesn't make sense for Poseidon2.
impl<F: PrimeField, const N: usize> Chip<F> for Poseidon2ExternalChip<N> {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let mut new_field_events = Vec::new();

        for i in 0..segment.poseidon2_external_events.len() {
            let event = segment.poseidon2_external_events[i];

            // TODO: Prinf-debugging statement. Remove this.
            // if i == 0 {
            //     println!("event: {:#?}", event);
            // }

            let original_clock: u32 = event.clk;
            for round in 0..POSEIDON2_DEFAULT_EXTERNAL_ROUNDS {
                let mut row = [F::zero(); NUM_POSEIDON2_EXTERNAL_COLS];
                let cols: &mut Poseidon2ExternalCols<F> = row.as_mut_slice().borrow_mut();
                cols.0.segment = F::from_canonical_u32(segment.index);
                cols.0.clk = F::from_canonical_u32(original_clock + (8 * N * round) as u32);
                for j in 0..N {
                    cols.0.state_ptr = F::from_canonical_u32(event.state_ptr);
                    cols.0.mem[round]
                        .populate_read(event.state_reads[round][j], &mut new_field_events);
                    cols.0.mem_addr[round] =
                        F::from_canonical_u32(event.state_ptr + (j * 4) as u32);

                    // TODO: Remove this printf-debugging statement.
                    // println!("new_field_events: {:?}", new_field_events);
                    println!(
                        "event.state_reads[{}].value: {:?}",
                        j, event.state_reads[round][j].value,
                    );
                }

                // TODO: This is where I do the calculation. For now, I wont' do anything, and write
                // back what I got.

                for j in 0..N {
                    cols.0.mem[round]
                        .populate_write(event.state_writes[round][j], &mut new_field_events);
                    cols.0.mem_addr[round] =
                        F::from_canonical_u32(event.state_ptr + (j * 4) as u32);

                    println!(
                        "event.state_write[{}].value: {:?}",
                        j, event.state_writes[round][j].value,
                    );
                }

                // TODO: I need to figure out whether I need both or I only need one of these.
                cols.0.is_real = F::one();
                cols.0.is_external = F::one();
                rows.push(row);
            }
        }

        segment.field_events.extend(new_field_events);

        let nb_rows = rows.len();
        let mut padded_nb_rows = nb_rows.next_power_of_two();
        if padded_nb_rows == 2 || padded_nb_rows == 1 {
            padded_nb_rows = 4;
        }

        for _ in nb_rows..padded_nb_rows {
            let row = [F::zero(); NUM_POSEIDON2_EXTERNAL_COLS];
            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_POSEIDON2_EXTERNAL_COLS,
        )
    }

    fn name(&self) -> String {
        "Poseidon2External".to_string()
    }
}
