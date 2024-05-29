use crate::{io::SP1PublicValues, runtime::execution_report::ExecutionReport};

/// Contains result of execution along with an [ExecutionReport].
pub struct ExecutionResult {
    /// Public values for Prover.
    pub values: SP1PublicValues,
    /// Statistics of program execution.
    pub report: ExecutionReport,
}
