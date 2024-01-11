use std::mem::transmute;

use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    air::Word,
    precompiles::sha256_extend::{ShaExtendCols, NUM_SHA_EXTEND_COLS},
    runtime::Segment,
    utils::Chip,
};

use super::ShaExtendChip;

impl<F: PrimeField> Chip<F> for ShaExtendChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        for i in 0..segment.sha_events.len() {
            let (
                clk,
                w_ptr,
                mut w,
                w_i_minus_15_records,
                w_i_minus_2_records,
                w_i_minus_16_records,
                w_i_minus_7_records,
                w_i_records,
            ) = segment.sha_events[i].clone();
            println!("INIT CLK = {}", clk);
            for j in 0..48usize {
                let mut row = [F::zero(); NUM_SHA_EXTEND_COLS];
                let cols: &mut ShaExtendCols<F> = unsafe { transmute(&mut row) };

                cols.populate_flags(j);
                cols.segment = F::one();
                cols.clk = F::from_canonical_u32(clk);
                cols.w_ptr = F::from_canonical_u32(w_ptr);

                self.populate_access(
                    &mut cols.w_i_minus_15,
                    w[16 + j - 15],
                    Some(w_i_minus_15_records[j]),
                );
                self.populate_access(
                    &mut cols.w_i_minus_2,
                    w[16 + j - 2],
                    Some(w_i_minus_2_records[j]),
                );
                self.populate_access(
                    &mut cols.w_i_minus_16,
                    w[16 + j - 16],
                    Some(w_i_minus_16_records[j]),
                );
                self.populate_access(
                    &mut cols.w_i_minus_7,
                    w[16 + j - 7],
                    Some(w_i_minus_7_records[j]),
                );

                // Compute `s0`.
                // cols.w_i_minus_15.value = Word::from(w[16 + j - 15]);
                cols.w_i_minus_15_rr_7.populate(cols.w_i_minus_15.value, 7);
                cols.w_i_minus_15_rr_18
                    .populate(cols.w_i_minus_15.value, 18);
                cols.w_i_minus_15_rs_3.populate(cols.w_i_minus_15.value, 3);
                cols.s0.populate(
                    cols.w_i_minus_15_rr_7.value,
                    cols.w_i_minus_15_rr_18.value,
                    cols.w_i_minus_15_rs_3.value,
                );

                // Compute `s1`.
                cols.w_i_minus_2.value = Word::from(w[16 + j - 2]);
                cols.w_i_minus_2_rr_17.populate(cols.w_i_minus_2.value, 17);
                cols.w_i_minus_2_rr_19.populate(cols.w_i_minus_2.value, 19);
                cols.w_i_minus_2_rs_10.populate(cols.w_i_minus_2.value, 10);
                cols.s1.populate(
                    cols.w_i_minus_2_rr_17.value,
                    cols.w_i_minus_2_rr_19.value,
                    cols.w_i_minus_2_rs_10.value,
                );

                // Compute `s2`.
                cols.w_i_minus_16.value = Word::from(w[16 + j - 16]);
                cols.w_i_minus_7.value = Word::from(w[16 + j - 7]);
                cols.s2.populate(
                    cols.w_i_minus_16.value,
                    cols.s0.value,
                    cols.w_i_minus_7.value,
                    cols.s1.value,
                );

                // Write `s2` to `w[i]`.
                w[16 + j] = u32::from_le_bytes(
                    cols.s2
                        .value
                        .0
                        .map(|x| x.to_string().parse::<u8>().unwrap()),
                );
                self.populate_access(&mut cols.w_i, w[16 + j], Some(w_i_records[j]));

                cols.is_real = F::one();
                rows.push(row);
            }
        }

        let nb_rows = rows.len();
        for i in nb_rows..nb_rows.next_power_of_two() {
            let mut row = [F::zero(); NUM_SHA_EXTEND_COLS];
            let cols: &mut ShaExtendCols<F> = unsafe { transmute(&mut row) };
            cols.populate_flags(i);
            rows.push(row);
        }

        println!("nb_rows={}", nb_rows);

        // Convert the trace to a row major matrix.
        let trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHA_EXTEND_COLS,
        );

        trace
    }
}
