use std::{collections::HashMap, fmt::Display};

use serde::{Deserialize, Serialize};
use slop_algebra::Field;

/// The underlying values that back the constraint compiler.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum IrVar<F> {
    /// Public inputs.
    Public(usize),
    /// Preprocessed inputs.
    Preprocessed(usize),
    /// Global columns.
    Global(usize),
    /// Columns.
    Main(usize),
    /// Constants.
    Constant(F),
    /// Inputs to function calls.
    InputArg(usize),
    /// Outputs to function calls.
    OutputArg(usize),
}

impl<F: Field> Display for IrVar<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IrVar::Public(i) => write!(f, "Public({i})"),
            IrVar::Preprocessed(i) => write!(f, "Preprocessed({i})"),
            IrVar::Global(i) => write!(f, "Global({i})"),
            IrVar::Main(i) => write!(f, "Main({i})"),
            IrVar::Constant(c) => write!(f, "{c}"),
            IrVar::InputArg(i) => write!(f, "Input({i})"),
            IrVar::OutputArg(i) => write!(f, "Output({i})"),
        }
    }
}

impl<F: Field> IrVar<F> {
    /// Convert to Lean syntax based on context (chip vs operation)
    pub fn to_lean(&self, is_operation: bool, input_mapping: &HashMap<usize, String>) -> String {
        match self {
            IrVar::Main(i) => format!("Main[{i}]"),
            IrVar::InputArg(i) => {
                if is_operation {
                    input_mapping.get(i).map_or(format!("I[{i}]"), std::clone::Clone::clone)
                } else {
                    // In chip context, InputArg shouldn't appear
                    format!("InputArg({i})")
                }
            }
            IrVar::Constant(c) => format!("{c}"),
            IrVar::Public(i) => format!("Public[{i}]"),
            IrVar::Preprocessed(i) => format!("Preprocessed[{i}]"),
            IrVar::Global(i) => format!("Global[{i}]"),
            IrVar::OutputArg(i) => format!("Output[{i}]"),
        }
    }
}

/// Function context to keep track of the (number of) inputs and outputs within
/// a function call.
pub struct FuncCtx {
    pub(crate) input_idx: usize,
    pub(crate) output_idx: usize,
}

impl FuncCtx {
    /// Constructs a new [`FuncCtx`].
    #[must_use]
    pub fn new() -> Self {
        Self { input_idx: 0, output_idx: 0 }
    }
}

impl Default for FuncCtx {
    fn default() -> Self {
        Self::new()
    }
}
