use std::mem::MaybeUninit;

use crate::{septic_digest::SepticDigest, MachineRecord};
use slop_air::BaseAir;
use slop_algebra::Field;
use slop_matrix::dense::RowMajorMatrix;
pub use sp1_derive::MachineAir;

#[macro_export]
/// Macro to get the name of a chip.
macro_rules! chip_name {
    ($chip:ident, $field:ty) => {
        <$chip as MachineAir<$field>>::name(&$chip {})
    };
}

/// An AIR that is part of a multi table AIR arithmetization.
pub trait MachineAir<F: Field>: BaseAir<F> + 'static + Send + Sync {
    /// The execution record containing events for producing the air trace.
    type Record: MachineRecord;

    /// The program that defines the control flow of the machine.
    type Program: MachineProgram<F>;

    /// Customizes the program for the machine.
    fn customize_program(&self, program: Self::Program) -> Self::Program {
        // By default, the machine does not customize the program.
        program
    }

    /// A unique identifier for this AIR as part of a machine.
    fn name(&self) -> &str;

    /// A list of column names. The length should equal `self.width()`.
    fn column_names(&self) -> Vec<String> {
        // Default implementation returns generic column names.
        (0..self.width()).map(|i| format!("col_{i}")).collect()
    }

    /// The number of rows in the trace, if the chip is included.
    ///
    /// **Warning**:: if the chip is not included, `num_rows` is allowed to return anything.
    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        self.num_rows_for(input, None)
    }

    /// Generate the trace for a given execution record.
    ///
    /// - `input` is the execution record containing the events to be written to the trace.
    /// - `output` is the execution record containing events that the `MachineAir` can add to the
    ///   record such as byte lookup requests.
    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let padded_nb_rows = self.num_rows(input).unwrap();
        let num_columns = <Self as BaseAir<F>>::width(self);
        let mut values: Vec<F> = Vec::with_capacity(padded_nb_rows * num_columns);
        self.generate_trace_into(input, output, values.spare_capacity_mut());
        unsafe {
            values.set_len(padded_nb_rows * num_columns);
        }
        RowMajorMatrix::new(values, num_columns)
    }

    /// Generate the dependencies for a given execution record.
    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        self.generate_trace(input, output);
    }

    /// Generate the trace into a slice of `MaybeUninit<F>`.
    fn generate_trace_into(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
        buffer: &mut [MaybeUninit<F>],
    ) {
        self.generate_trace_into_for(input, output, buffer, None);
    }

    /// Whether this execution record contains events for this air.
    fn included(&self, shard: &Self::Record) -> bool {
        self.included_for(shard, None)
    }

    /// The number of rows for a given group context.
    /// `None` = software events, `Some(idx)` = APC group.
    /// Only chips used in APC should implement this.
    fn num_rows_for(&self, _input: &Self::Record, _apc_id: Option<usize>) -> Option<usize> {
        unimplemented!("only chips used in APC should implement this")
    }

    /// Generate the trace for a given group context.
    /// Default: allocates buffer and calls `generate_trace_into_for`.
    fn generate_trace_for(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
        apc_id: Option<usize>,
    ) -> RowMajorMatrix<F> {
        let padded_nb_rows = self.num_rows_for(input, apc_id).unwrap();
        let num_columns = <Self as BaseAir<F>>::width(self);
        let mut values: Vec<F> = Vec::with_capacity(padded_nb_rows * num_columns);
        self.generate_trace_into_for(input, output, values.spare_capacity_mut(), apc_id);
        unsafe {
            values.set_len(padded_nb_rows * num_columns);
        }
        RowMajorMatrix::new(values, num_columns)
    }

    /// Generate trace into buffer for a given group context.
    /// Only chips used in APC should implement this.
    fn generate_trace_into_for(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _buffer: &mut [MaybeUninit<F>],
        _apc_id: Option<usize>,
    ) {
        unimplemented!("only chips used in APC should implement this")
    }

    /// Whether this air is included for a given group context.
    /// Only chips used in APC should implement this.
    fn included_for(&self, _shard: &Self::Record, _apc_id: Option<usize>) -> bool {
        unimplemented!("only chips used in APC should implement this")
    }

    /// The width of the preprocessed trace.
    fn preprocessed_width(&self) -> usize {
        0
    }

    /// The number of rows in the preprocessed trace
    fn preprocessed_num_rows(&self, _program: &Self::Program) -> Option<usize> {
        None
    }

    /// The number of rows in the preprocessed trace using the program and the instr len.
    fn preprocessed_num_rows_with_instrs_len(
        &self,
        _program: &Self::Program,
        _instrs_len: usize,
    ) -> Option<usize> {
        None
    }

    /// Generate the preprocessed trace into a slice of `MaybeUninit<F>`.
    fn generate_preprocessed_trace_into(&self, _: &Self::Program, _: &mut [MaybeUninit<F>]) {}

    /// Generate the preprocessed trace given a specific program.
    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        if self.preprocessed_width() == 0 {
            return None;
        }

        let padded_nb_rows = self.preprocessed_num_rows(program).unwrap();
        let num_columns = self.preprocessed_width();
        let mut values: Vec<F> = Vec::with_capacity(padded_nb_rows * num_columns);
        self.generate_preprocessed_trace_into(program, values.spare_capacity_mut());

        unsafe {
            values.set_len(padded_nb_rows * num_columns);
        }

        Some(RowMajorMatrix::new(values, num_columns))
    }
}

/// A program that defines the control flow of a machine through a program counter.
pub trait MachineProgram<F>: Send + Sync {
    /// Gets the starting program counter.
    fn pc_start(&self) -> [F; 3];
    /// Gets the initial global cumulative sum.
    fn initial_global_cumulative_sum(&self) -> SepticDigest<F>;
    /// Gets the flag indicating if untrusted programs are allowed.
    fn enable_untrusted_programs(&self) -> F;
}
