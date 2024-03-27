use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use super::{air::BYTE_MULT_INDICES, ByteChip};
use crate::{air::MachineAir, runtime::ExecutionRecord};

pub const NUM_ROWS: usize = 1 << 16;

impl<F: Field> MachineAir<F> for ByteChip<F> {
    type Record = ExecutionRecord;

    fn name(&self) -> String {
        "Byte".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let (mut trace, event_map) = ByteChip::trace_and_map();

        for (lookup, mult) in input.byte_lookups.iter() {
            let (row, index) = event_map[lookup];

            // Get the column index for the multiplicity.
            let idx = BYTE_MULT_INDICES[index];
            // Update the trace value
            trace.row_mut(row)[idx] += F::from_canonical_usize(*mult);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.byte_lookups.is_empty()
    }
}
