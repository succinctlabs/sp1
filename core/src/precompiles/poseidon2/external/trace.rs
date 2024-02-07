use std::borrow::BorrowMut;

use p3_field::{Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;

use crate::{runtime::Segment, utils::Chip};

use super::{
    columns::{
        Poseidon2ExternalCols, NUM_POSEIDON2_EXTERNAL_COLS, P2_EXTERNAL_ROUND_COUNT,
        P2_ROUND_CONSTANTS,
    },
    Poseidon2External1Chip, P2_WIDTH,
};

// TODO: I don't know how to combine F and PF.
impl<PF: PrimeField, const WIDTH: usize, F: Field> Chip<PF> for Poseidon2External1Chip<F, WIDTH> {
    // TODO: The vast majority of this logic can be shared with the second external round.
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<PF> {
        let mut rows = Vec::new();

        let mut new_field_events = Vec::new();

        for i in 0..segment.poseidon2_external_1_events.len() {
            let event = segment.poseidon2_external_1_events[i];

            let mut clk = event.clk;
            for round in 0..P2_EXTERNAL_ROUND_COUNT {
                let mut row = [PF::zero(); NUM_POSEIDON2_EXTERNAL_COLS];
                let cols: &mut Poseidon2ExternalCols<PF> = row.as_mut_slice().borrow_mut();

                // Assign basic values to the columns.
                {
                    cols.segment = PF::from_canonical_u32(segment.index);

                    cols.clk = PF::from_canonical_u32(clk);

                    cols.round_number = PF::from_canonical_u32(round as u32);
                    cols.is_round_n[round] = PF::one();
                    for i in 0..P2_WIDTH {
                        cols.round_constant[i] =
                            PF::from_canonical_u32(P2_ROUND_CONSTANTS[round][i]);
                    }
                }

                // Read.
                for i in 0..WIDTH {
                    cols.state_ptr = PF::from_canonical_u32(event.state_ptr);
                    cols.mem_reads[i].populate(event.state_reads[round][i], &mut new_field_events);
                    cols.mem_addr[i] = PF::from_canonical_u32(event.state_ptr + (i * 4) as u32);
                    cols.mem_read_clk[i] = PF::from_canonical_u32(clk);
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
                    .map(PF::from_canonical_u32);

                // Add the round constant to the state.
                let result_add_rc = cols.add_rc.populate(&input_state, round);

                // Sbox.
                let result_sbox = cols.sbox.populate(&result_add_rc);

                // External linear permute
                let result_external_linear_permute =
                    cols.external_linear_permute.populate(&result_sbox);

                // Write.
                for i in 0..WIDTH {
                    // TODO: I need to pass in the results of calculation (add_Rc, sbox, ...)
                    // But for now, I'll leave these as is, one problem at a time!
                    cols.mem_writes[i]
                        .populate(event.state_writes[round][i], &mut new_field_events);
                    cols.mem_addr[i] = PF::from_canonical_u32(event.state_ptr + (i * 4) as u32);
                    cols.mem_write_clk[i] = PF::from_canonical_u32(clk);
                    clk += 4;

                    assert_eq!(
                        result_external_linear_permute[i],
                        PF::from_canonical_u32(event.state_writes[round][i].value)
                    );

                    if round == P2_EXTERNAL_ROUND_COUNT - 1 {
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

                println!("clk: {:?}", cols.clk);
                println!("mem_read_clk: {:?}", cols.mem_read_clk);
                println!("mem_write_clk: {:?}", cols.mem_write_clk);

                // TODO: I need to figure out whether I need both or I only need one of these.
                cols.is_real = PF::one();
                cols.is_external = PF::one();
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
            let row = [PF::zero(); NUM_POSEIDON2_EXTERNAL_COLS];
            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_POSEIDON2_EXTERNAL_COLS,
        )
    }

    fn name(&self) -> String {
        "Poseidon2External1".to_string()
    }
}
