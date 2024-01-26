use std::mem::transmute;

use alloc::vec::Vec;

use p3_field::PrimeField32;
use p3_keccak_air::generate_trace_rows;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    precompiles::keccak256::{
        columns::{KeccakCols, NUM_KECCAK_COLS},
        NUM_ROUNDS,
    },
    runtime::Segment,
    utils::Chip,
};

use super::KeccakPermuteChip;

impl<F: PrimeField32> Chip<F> for KeccakPermuteChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        const SEGMENT_NUM: u32 = 1;
        let mut new_field_events = Vec::new();
        for event in segment.keccak_permute_events.iter() {
            // First get the trace for the plonky3 keccak air.
            let p3_keccak_trace = generate_trace_rows::<F>(vec![event.pre_state]);

            // Create all the rows for the permutation.
            let mut rows = Vec::new();
            for (i, p3_keccak_row) in (0..NUM_ROUNDS).zip(p3_keccak_trace.rows()) {
                let mut row = [F::zero(); NUM_KECCAK_COLS];
                let col: &mut KeccakCols<F> = unsafe { transmute(&mut row) };
                col.segment = F::from_canonical_u32(SEGMENT_NUM);
                col.clk = F::from_canonical_u32(event.clk + i as u32 * 4);

                // copy over the p3_keccak_row to the row
                row[self.p3_keccak_col_range.start..self.p3_keccak_col_range.end]
                    .copy_from_slice(p3_keccak_row);

                // if this is the first row, then populate read memory accesses
                if i == 0 {
                    for (j, read_record) in event.state_read_records.iter().enumerate() {
                        col.state_mem[j].populate_read(*read_record, &mut new_field_events);
                    }

                    col.state_addr = F::from_canonical_u32(event.state_addr);
                }

                // if this is the last row, then populate write memory accesses
                let last_row_num = NUM_ROUNDS - 1;
                if i == last_row_num {
                    for (j, write_record) in event.state_write_records.iter().enumerate() {
                        col.state_mem[j].populate_write(*write_record, &mut new_field_events);
                    }

                    col.state_addr = F::from_canonical_u32(event.state_addr);
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
            let row = [F::zero(); NUM_KECCAK_COLS];
            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_KECCAK_COLS,
        )
    }

    fn name(&self) -> String {
        "KeccakPermute".to_string()
    }
}
