use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use super::{air::BYTE_MULT_INDICES, ByteChip};
use crate::{runtime::Segment, utils::Chip};

pub const NUM_ROWS: usize = 1 << 16;

impl<F: Field> Chip<F> for ByteChip<F> {
    fn name(&self) -> String {
        "Byte".to_string()
    }

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut trace = self.initial_trace.clone();

        for (lookup, mult) in segment.byte_lookups.iter() {
            let (row, index) = self.event_map[lookup];

            // Get the column index for the multiplicity.
            let idx = BYTE_MULT_INDICES[index];
            // Update the trace value
            trace.row_mut(row)[idx] += F::from_canonical_usize(*mult);
        }

        trace
    }
}
