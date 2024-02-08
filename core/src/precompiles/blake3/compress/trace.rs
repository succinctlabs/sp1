use crate::precompiles::blake3::compress::columns::NUM_BLAKE3_COMPRESS_INNER_COLS;
use crate::precompiles::blake3::Blake3CompressInnerChip;

use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{runtime::Segment, utils::Chip};

impl<F: PrimeField> Chip<F> for Blake3CompressInnerChip {
    // TODO: The vast majority of this logic can be shared with the second external round.
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let mut new_field_events = Vec::new();

        for i in 0..segment.blake3_compress_inner_events.len() {
            // let event = segment.blake3_external_1_events[i];

            // let mut clk = event.clk;
            // for round in 0..P2_EXTERNAL_ROUND_COUNT {
            //     let mut row = [F::zero(); NUM_BLAKE3_COMPRESS_INNER_COLS];
            //     let cols: &mut Blake3CompressInnerCols<F> = row.as_mut_slice().borrow_mut();

            //     // Assign basic values to the columns.
            //     {
            //         cols.segment = F::from_canonical_u32(segment.index);

            //         cols.clk = F::from_canonical_u32(clk);

            //         cols.round_number = F::from_canonical_u32(round as u32);
            //         cols.is_round_n[round] = F::one();
            //         for i in 0..P2_WIDTH {
            //             cols.round_constant[i] = F::from_wrapped_u32(P2_ROUND_CONSTANTS[round][i]);
            //         }
            //     }

            //     // Read.
            //     for i in 0..P2_WIDTH {
            //         cols.state_ptr = F::from_canonical_u32(event.state_ptr);
            //         cols.mem_reads[i].populate(event.state_reads[round][i], &mut new_field_events);
            //         cols.mem_addr[i] = F::from_canonical_u32(event.state_ptr + (i * 4) as u32);
            //         clk += 4;
            //     }

            //     let input_state = event.state_reads[round]
            //         .map(|read| read.value)
            //         .map(F::from_canonical_u32);

            //     // Add the round constant to the state.
            //     let result_add_rc = cols.add_rc.populate(&input_state, round);

            //     // Sbox.
            //     let result_sbox = cols.sbox.populate(&result_add_rc);

            //     // External linear permute
            //     let result_external_linear_permute =
            //         cols.external_linear_permute.populate(&result_sbox);

            //     // Write.
            //     for i in 0..P2_WIDTH {
            //         cols.mem_writes[i]
            //             .populate(event.state_writes[round][i], &mut new_field_events);
            //         cols.mem_addr[i] = F::from_canonical_u32(event.state_ptr + (i * 4) as u32);
            //         clk += 4;

            //         assert_eq!(
            //             result_external_linear_permute[i],
            //             F::from_canonical_u32(event.state_writes[round][i].value)
            //         );
            //     }

            //     cols.is_real = F::one();
            //     rows.push(row);
            // }
        }

        segment.field_events.extend(new_field_events);

        let nb_rows = rows.len();
        let mut padded_nb_rows = nb_rows.next_power_of_two();
        if padded_nb_rows == 2 || padded_nb_rows == 1 {
            padded_nb_rows = 4;
        }

        for _ in nb_rows..padded_nb_rows {
            let row = [F::zero(); NUM_BLAKE3_COMPRESS_INNER_COLS];
            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BLAKE3_COMPRESS_INNER_COLS,
        )
    }

    fn name(&self) -> String {
        "Blake3External1".to_string()
    }
}
