use std::borrow::BorrowMut;

use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{runtime::Segment, utils::Chip};

use super::{
    columns::{
        Poseidon2ExternalCols, NUM_POSEIDON2_EXTERNAL_COLS,
        POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS, POSEIDON2_ROUND_CONSTANTS,
    },
    Poseidon2ExternalChip, NUM_LIMBS_POSEIDON2_STATE,
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

        for i in 0..segment.poseidon2_external_1_events.len() {
            let event = segment.poseidon2_external_1_events[i];

            // TODO: Printf-debugging statement. Remove this.
            // if i == 0 {
            //     println!("event: {:#?}", event);
            // }

            let mut clk = event.clk;
            for round in 0..POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS {
                let mut row = [F::zero(); NUM_POSEIDON2_EXTERNAL_COLS];
                let cols: &mut Poseidon2ExternalCols<F> = row.as_mut_slice().borrow_mut();

                // Assign basic values to the columns.
                {
                    cols.0.segment = F::from_canonical_u32(segment.index);

                    // Increment the clock by 4 * (the number of reads + writes for this round).
                    cols.0.clk = F::from_canonical_u32(clk);

                    cols.0.round_number = F::from_canonical_u32(round as u32);
                    cols.0.is_round_n[round] = F::one();
                    for i in 0..NUM_LIMBS_POSEIDON2_STATE {
                        cols.0.round_constant[i] =
                            F::from_canonical_u32(POSEIDON2_ROUND_CONSTANTS[round][i]);
                    }
                }

                // Read.
                for i in 0..NUM_WORDS_STATE {
                    cols.0.state_ptr = F::from_canonical_u32(event.state_ptr);
                    cols.0.mem_reads[i]
                        .populate(event.state_reads[round][i], &mut new_field_events);
                    cols.0.mem_addr[i] = F::from_canonical_u32(event.state_ptr + (i * 4) as u32);
                    cols.0.mem_read_clk[i] = F::from_canonical_u32(clk);
                    clk += 4;

                    // TODO: Remove this printf-debugging statement.
                    // println!("new_field_events: {:?}", new_field_events);
                    if round == 0 {
                        println!(
                            "{}th limb of input: {:?}",
                            i, event.state_reads[round][i].value,
                        );
                    }
                }

                let input_state = event.state_reads[round]
                    .map(|read| read.value)
                    .map(F::from_canonical_u32);

                // Add the round constant to the state.
                let result_add_rc = cols.0.add_rc.populate(&input_state, round);

                // Sbox.
                let result_sbox = cols.0.sbox.populate(&result_add_rc);

                // External linear permute
                let result_external_linear_permute =
                    cols.0.external_linear_permute.populate(&result_sbox);

                // Write.
                for i in 0..NUM_WORDS_STATE {
                    // TODO: I need to pass in the results of calculation (add_Rc, sbox, ...)
                    // But for now, I'll leave these as is, one problem at a time!
                    cols.0.mem_writes[i]
                        .populate(event.state_writes[round][i], &mut new_field_events);
                    cols.0.mem_addr[i] = F::from_canonical_u32(event.state_ptr + (i * 4) as u32);
                    cols.0.mem_write_clk[i] = F::from_canonical_u32(clk);
                    clk += 4;

                    assert_eq!(
                        result_external_linear_permute[i],
                        F::from_canonical_u32(event.state_writes[round][i].value)
                    );

                    if round == POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS - 1 {
                        println!(
                            "{}th limb of output: {:?}",
                            i, event.state_writes[round][i].value,
                        );
                    }
                    println!(
                        "event.state_write[{}].value: {:?}",
                        i, event.state_writes[round][i].value,
                    );
                }

                // TODO: I need to figure out whether I need both or I only need one of these.
                cols.0.is_real = F::one();
                cols.0.is_external = F::one();
                // if round == 0 {
                //     println!("cols: {:#?}", cols);
                // }
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
