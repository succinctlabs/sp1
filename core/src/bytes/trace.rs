use std::collections::BTreeMap;

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::bytes::air::NUM_BYTE_COLS;

use super::{ByteChip, ByteLookupEvent};

pub const NUM_ROWS: usize = 1 << 16;

impl<F: Field> ByteChip<F> {
    pub(crate) fn generate_trace_from_events(
        &self,
        byte_lookups: &BTreeMap<ByteLookupEvent, usize>,
    ) -> RowMajorMatrix<F> {
        let mut trace = self.initial_trace.clone();

        // for (lookup, mult) in byte_lookups.iter() {
        //     let (row, index) = self.table_map[lookup];

        //     // Get the column index for the multiplicity.
        //     let mult_idx = row * NUM_BYTE_COLS + BYTE_MULT_INDICES[index];
        //     // Update the trace value
        //     trace_rows[mult_idx] = F::from_canonical_usize(*mult);
        // }

        trace
    }
}
