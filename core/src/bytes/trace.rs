use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use super::{air::BYTE_MULT_INDICES, ByteChip};
use crate::{
    air::{ExecutionAir, MachineAir},
    runtime::{ExecutionRecord, Host, Program},
};

pub const NUM_ROWS: usize = 1 << 16;

impl<F: Field> MachineAir<F> for ByteChip {
    fn name(&self) -> String {
        "Byte".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        10
    }

    fn generate_preprocessed_trace(&self, _program: &Program) -> Option<RowMajorMatrix<F>> {
        let values = (0..10 * NUM_ROWS)
            .map(|i| F::from_canonical_usize(i))
            .collect();

        Some(RowMajorMatrix::new(values, 10))
    }
}

impl<F: Field, H: Host<Record = ExecutionRecord>> ExecutionAir<F, H> for ByteChip {
    fn shard(&self, input: &ExecutionRecord, outputs: &mut Vec<ExecutionRecord>) {
        outputs[0].byte_lookups = input.byte_lookups.clone();
    }

    fn include(&self, record: &ExecutionRecord) -> bool {
        !record.byte_lookups.is_empty()
    }

    fn generate_trace(&self, record: &ExecutionRecord, host: &mut H) -> RowMajorMatrix<F> {
        let (mut trace, event_map) = ByteChip::trace_and_map::<F>();

        for (lookup, mult) in record.byte_lookups.iter() {
            let (row, index) = event_map[lookup];

            // Get the column index for the multiplicity.
            let idx = BYTE_MULT_INDICES[index];
            // Update the trace value
            trace.row_mut(row)[idx] += F::from_canonical_usize(*mult);
        }

        trace
    }
}
