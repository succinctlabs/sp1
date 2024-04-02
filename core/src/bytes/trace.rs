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
        // Use a dummy shard, since we don't really care about this in the trace.
        // TODO: I think we can heavily optimize this process and use it as a const.
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
        println!("input index: {:?}", input.index);
        println!("input {:?}", input);
        println!("input byte lookups: {:?}", input.byte_lookups);
        let shard = input.index;
        let (_, event_map) = Self::trace_and_map(shard);

        let mut trace = RowMajorMatrix::new(
            vec![F::zero(); NUM_BYTE_MULT_COLS * NUM_ROWS],
            NUM_BYTE_MULT_COLS,
        );

        for (lookup, mult) in input.byte_lookups[&shard].iter() {
            let (row, index) = event_map[lookup];

            // Update the trace multiplicity
            trace.row_mut(row)[index] += F::from_canonical_usize(*mult);

            // Set the shard column as the current shard.
            trace.row_mut(row)[NUM_BYTE_MULT_COLS - 1] = F::from_canonical_u32(shard);
        }

        trace
    }

    fn included(&self, _shard: &Self::Record) -> bool {
        true
    }
}
