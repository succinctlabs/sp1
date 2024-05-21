use std::borrow::BorrowMut;

use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use sp1_core::air::MachineAir;

use super::{
    columns::{RangeCheckMultCols, NUM_RANGE_CHECK_MULT_COLS, NUM_RANGE_CHECK_PREPROCESSED_COLS},
    RangeCheckChip,
};
use crate::runtime::{ExecutionRecord, RecursionProgram};

pub const NUM_ROWS: usize = 1 << 16;

impl<F: PrimeField32> MachineAir<F> for RangeCheckChip<F> {
    type Record = ExecutionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "RangeCheck".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_RANGE_CHECK_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let (trace, _) = Self::trace_and_map();

        Some(trace)
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let (_, event_map) = Self::trace_and_map();

        let mut trace = RowMajorMatrix::new(
            vec![F::zero(); NUM_RANGE_CHECK_MULT_COLS * NUM_ROWS],
            NUM_RANGE_CHECK_MULT_COLS,
        );

        for (lookup, mult) in input.range_check_events.iter() {
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
