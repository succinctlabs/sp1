use p3_air::BaseAir;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::stark::MachineRecord;

pub use sp1_derive::MachineAir;

/// An AIR that is part of a Risc-V AIR arithmetization.
pub trait MachineAir<F: Field>: BaseAir<F> {
    /// The execution record containing events for producing the air trace.
    type Record: MachineRecord;

    type Program;

    /// A unique identifier for this AIR as part of a machine.
    fn name(&self) -> String;

    /// Generate the trace for a given execution record.
    ///
    /// - `input` is the execution record containing the events to be written to the trace.
    /// - `output` is the execution record containing events that the `MachineAir` can add to
    ///    the record such as byte lookup requests.
    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F>;

    /// Generate the dependencies for a given execution record.
    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        self.generate_trace(input, output);
    }

    /// Whether this execution record contains events for this air.
    fn included(&self, shard: &Self::Record) -> bool;

    fn preprocessed_width(&self) -> usize {
        0
    }

    /// Generate the preprocessed trace given a specific program.
    #[allow(unused_variables)]
    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        None
    }
}
