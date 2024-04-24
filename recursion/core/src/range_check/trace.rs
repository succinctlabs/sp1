use std::borrow::BorrowMut;

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use super::{
    columns::{ByteMultCols, NUM_BYTE_MULT_COLS, NUM_BYTE_PREPROCESSED_COLS},
    ByteChip,
};

pub const NUM_ROWS: usize = 1 << 16;

impl<F: Field> MachineAir<F> for RangeCheckChip<F> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "RangeCheck".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_RANGE_CHECK_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        // TODO: We should be able to make this a constant. Also, trace / map should be separate.
        // Since we only need the trace and not the map, we can just pass 0 as the shard.
        let (trace, _) = Self::trace_and_map(0);

        Some(trace)
    }

    fn generate_dependencies(&self, _input: &ExecutionRecord, _output: &mut ExecutionRecord) {
        // Do nothing since this chip has no dependencies.
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let (_, event_map) = Self::trace_and_map(shard);

        let mut trace = RowMajorMatrix::new(
            vec![F::zero(); NUM_RANGE_CHECK_MULT_COLS * NUM_ROWS],
            NUM_RANGE_CHECK_MULT_COLS,
        );

        for (lookup, mult) in input.range_check_lookups.iter() {
            let (row, index) = event_map[lookup];
            let cols: &mut RangeCheckMultCols<F> = trace.row_mut(row).borrow_mut();

            // Update the trace multiplicity
            cols.multiplicities[index] += F::from_canonical_usize(*mult);
        }

        trace
    }

    fn included(&self, _shard: &Self::Record) -> bool {
        true
    }
}
