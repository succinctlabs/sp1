use p3_air::BaseAir;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::{runtime::Program, stark::MachineRecord};

pub use sp1_derive::MachineAir;

/// An AIR that is part of a Risc-V AIR arithmetization.
pub trait MachineAir<F: Field>: BaseAir<F> {
    type Record: MachineRecord;

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

    /// The number of preprocessed columns in the trace.
    fn preprocessed_width(&self) -> usize {
        0
    }

    #[allow(unused_variables)]
    fn generate_preprocessed_trace(&self, program: &Program) -> Option<RowMajorMatrix<F>> {
        None
    }

    fn included(&self, shard: &Self::Record) -> bool;
}
