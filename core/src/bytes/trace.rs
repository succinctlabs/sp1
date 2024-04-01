use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use super::{
    columns::{NUM_BYTE_MULT_COLS, NUM_BYTE_PREPROCESSED_COLS},
    ByteChip,
};
use crate::{
    air::MachineAir,
    runtime::{ExecutionRecord, Program},
};

pub const NUM_ROWS: usize = 1 << 16;

impl<F: Field> MachineAir<F> for ByteChip<F> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Byte".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BYTE_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let (trace, _) = Self::trace_and_map();

        Some(trace)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let (_, event_map) = Self::trace_and_map();

        let mut trace = RowMajorMatrix::new(
            vec![F::zero(); NUM_BYTE_MULT_COLS * NUM_ROWS],
            NUM_BYTE_MULT_COLS,
        );

        for (lookup, mult) in input.byte_lookups.iter() {
            let (row, index) = event_map[lookup];

            // Update the trace multiplicity
            trace.row_mut(row)[index] += F::from_canonical_usize(*mult);
        }

        trace
    }

    fn included(&self, _shard: &Self::Record) -> bool {
        true
    }
}
