use std::mem::transmute;

use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    runtime::Segment,
    utils::{pad_to_power_of_two, Chip},
};

use super::{
    air::{FieldLTUCols, LTU_NB_BITS, NUM_FIELD_COLS},
    FieldLTUChip,
};

impl<F: PrimeField> Chip<F> for FieldLTUChip {
    fn name(&self) -> String {
        "FieldLTU".to_string()
    }

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let rows = segment
            .field_events
            .iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_FIELD_COLS];
                let cols: &mut FieldLTUCols<F> = unsafe { transmute(&mut row) };
                let diff = event.b - event.c + (1 << LTU_NB_BITS);
                cols.b = F::from_canonical_u32(event.b);
                cols.c = F::from_canonical_u32(event.c);
                for i in 0..cols.diff_bits.len() {
                    cols.diff_bits[i] = F::from_canonical_u32((diff >> i) & 1);
                }
                cols.lt = F::from_bool(event.ltu);
                cols.is_real = F::one();
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_FIELD_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_FIELD_COLS, F>(&mut trace.values);

        trace
    }
}
