use std::borrow::BorrowMut;

use alloc::vec::Vec;

use p3_field::PrimeField32;
use p3_keccak_air::{generate_trace_rows, NUM_ROUNDS};
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    precompiles::keccak256::{
        columns::{KeccakCols, NUM_KECCAK_COLS},
        STATE_SIZE,
    },
    runtime::Segment,
    utils::Chip,
};

use super::KeccakPermuteChip;

impl<F: PrimeField32> Chip<F> for KeccakPermuteChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Figure out number of total rows.
        let mut num_rows = (segment.keccak_permute_events.len() * NUM_ROUNDS).next_power_of_two();
        if num_rows < 4 {
            num_rows = 4;
        }
        let mut num_total_permutations = num_rows / NUM_ROUNDS;
        if num_rows % NUM_ROUNDS != 0 {
            num_total_permutations += 1;
        }
        let num_real_permutations = segment.keccak_permute_events.len();
        if num_total_permutations == 0 {
            num_total_permutations = 1;
        }

        const SEGMENT_NUM: u32 = 1;
        let mut new_field_events = Vec::new();
        let mut rows = Vec::new();
        for permutation_num in 0..num_total_permutations {
            let is_real_permutation = permutation_num < num_real_permutations;

            let event = if is_real_permutation {
                Some(&segment.keccak_permute_events[permutation_num])
            } else {
                None
            };

            let perm_input: [u64; STATE_SIZE] = if is_real_permutation {
                event.unwrap().pre_state
            } else {
                [0; STATE_SIZE]
            };

            let start_clk = if is_real_permutation {
                event.unwrap().clk
            } else {
                0
            };

            // First get the trace for the plonky3 keccak air.
            let p3_keccak_trace = generate_trace_rows::<F>(vec![perm_input]);

            // Create all the rows for the permutation.
            for (i, p3_keccak_row) in (0..NUM_ROUNDS).zip(p3_keccak_trace.rows()) {
                let mut row = [F::zero(); NUM_KECCAK_COLS];

                // copy over the p3_keccak_row to the row
                row[self.p3_keccak_col_range.start..self.p3_keccak_col_range.end]
                    .copy_from_slice(p3_keccak_row);

                let col: &mut KeccakCols<F> = row.as_mut_slice().borrow_mut();
                col.segment = F::from_canonical_u32(SEGMENT_NUM);
                col.clk = F::from_canonical_u32(start_clk + i as u32 * 4);

                // if this is the first row, then populate read memory accesses
                if i == 0 && is_real_permutation {
                    for (j, read_record) in event.unwrap().state_read_records.iter().enumerate() {
                        col.state_mem[j].populate_read(*read_record, &mut new_field_events);
                    }

                    col.state_addr = F::from_canonical_u32(event.unwrap().state_addr);
                    col.do_memory_check = F::one();
                }

                // if this is the last row, then populate write memory accesses
                let last_row_num = NUM_ROUNDS - 1;
                if i == last_row_num && is_real_permutation {
                    for (j, write_record) in event.unwrap().state_write_records.iter().enumerate() {
                        col.state_mem[j].populate_write(*write_record, &mut new_field_events);
                    }

                    col.state_addr = F::from_canonical_u32(event.unwrap().state_addr);
                    col.do_memory_check = F::one();
                }

                col.is_real = F::from_bool(is_real_permutation);

                rows.push(row);

                if rows.len() == num_rows {
                    break;
                }
            }
        }

        segment.field_events.extend(new_field_events);

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
