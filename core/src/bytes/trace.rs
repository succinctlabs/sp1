use std::collections::BTreeMap;

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    bytes::{
        air::{BYTE_MULT_INDICES, NUM_BYTE_COLS},
        NUM_BYTE_OPS,
    },
    runtime::Runtime,
};

use super::{ByteChip, ByteLookupEvent};

pub const NUM_ROWS: usize = 1 << 16;

impl<F: Field> ByteChip<F> {
    pub(crate) fn generate_trace_from_events(
        &self,
        byte_lookups: &BTreeMap<ByteLookupEvent, usize>,
    ) -> RowMajorMatrix<F> {
        let mut trace_rows = self.initial_trace_rows.clone();

        for (lookup, mult) in byte_lookups.iter() {
            let (row, index) = self.table_map[lookup];

            // Get the column index for the multiplicity.
            let mult_idx = row * NUM_BYTE_COLS + BYTE_MULT_INDICES[index];
            // Update the trace value
            trace_rows[mult_idx] += F::from_canonical_usize(*mult);
        }

        RowMajorMatrix::new(trace_rows, NUM_BYTE_COLS)
    }
}
