use std::borrow::BorrowMut;

use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{runtime::Segment, utils::Chip};

use super::{
    columns::{
        Poseidon2ExternalCols, NUM_POSEIDON2_EXTERNAL_COLS, POSEIDON2_DEFAULT_EXTERNAL_ROUNDS,
    },
    Poseidon2ExternalChip,
};

/// Poseidon2 external chip. `NUM_WORDS_STATE` is the number of words in the state. This has to be
/// consistent with the parameter in `Poseidon2ExternalCols`.
///
/// TODO: Do I really need this const generic? Or should I make a subset of the logic in
/// generate_trace use the const generic?
impl<F: PrimeField, const NUM_WORDS_STATE: usize> Chip<F>
    for Poseidon2ExternalChip<NUM_WORDS_STATE>
{
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let mut new_field_events = Vec::new();

        for i in 0..segment.poseidon2_external_events.len() {
            let event = segment.poseidon2_external_events[i];

            // TODO: Printf-debugging statement. Remove this.
            // if i == 0 {
            //     println!("event: {:#?}", event);
            // }

            let original_clock: u32 = event.clk;
            for round in 0..POSEIDON2_DEFAULT_EXTERNAL_ROUNDS {
                let mut row = [F::zero(); NUM_POSEIDON2_EXTERNAL_COLS];
                let cols: &mut Poseidon2ExternalCols<F> = row.as_mut_slice().borrow_mut();
                cols.0.segment = F::from_canonical_u32(segment.index);

                // Increment the clock by 4 * (the number of reads + writes for this round).
                cols.0.clk =
                    F::from_canonical_u32(original_clock + (8 * NUM_WORDS_STATE * round) as u32);

                // Read.
                for i in 0..NUM_WORDS_STATE {
                    cols.0.state_ptr = F::from_canonical_u32(event.state_ptr);
                    cols.0.mem[i].populate_read(event.state_reads[round][i], &mut new_field_events);
                    cols.0.mem_addr[i] = F::from_canonical_u32(event.state_ptr + (i * 4) as u32);

                    // TODO: Remove this printf-debugging statement.
                    // println!("new_field_events: {:?}", new_field_events);
                    println!(
                        "event.state_reads[{}].value: {:?}",
                        i, event.state_reads[round][i].value,
                    );
                }

                // TODO: This is where I do the calculation. For now, I won't do anything.

                // Write.
                for i in 0..NUM_WORDS_STATE {
                    cols.0.mem[i]
                        .populate_write(event.state_writes[round][i], &mut new_field_events);
                    cols.0.mem_addr[i] = F::from_canonical_u32(event.state_ptr + (i * 4) as u32);

                    println!(
                        "event.state_write[{}].value: {:?}",
                        i, event.state_writes[round][i].value,
                    );
                }

                // TODO: I need to figure out whether I need both or I only need one of these.
                cols.0.is_real = F::one();
                cols.0.is_external = F::one();
                if round == 0 {
                    println!("cols: {:#?}", cols);
                }
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
