use p3_air::BaseAir;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::runtime::{ExecutionRecord, Program};

/// An AIR that is part of a Risc-V AIR arithmetization.
pub trait MachineAir<F: Field>: BaseAir<F> {
    /// A unique identifier for this AIR as part of a machine.
    fn name(&self) -> String;

    /// Generate the trace for a given execution record.
    ///
    /// The mutable borrow of `record` allows a `MachineAir` to store additional information in the
    /// record, such as inserting events for other AIRs to process.
    fn generate_trace(&self, record: &mut ExecutionRecord) -> RowMajorMatrix<F>;

    fn shard(&self, input: &ExecutionRecord, outputs: &mut Vec<ExecutionRecord>);

    fn include(&self, record: &ExecutionRecord) -> bool;

    /// The number of preprocessed columns in the trace.
    fn preprocessed_width(&self) -> usize {
        0
    }

    #[allow(unused_variables)]
    fn preprocessed_trace(&self, program: &Program) -> Option<RowMajorMatrix<F>> {
        None
    }
}
