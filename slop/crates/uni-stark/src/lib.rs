//! The symbolic constraint layer for SLOP AIRs.
//!
//! Vendored from `p3-uni-stark` (0.4.3-succinct), reduced to the symbolic
//! pieces SP1 uses (the univariate STARK prover/verifier, folders, and config
//! are not used by SP1 and were dropped), and extended with the global trace
//! group: [`Entry::Global`], a global matrix in [`SymbolicAirBuilder`], and a
//! `global_width` parameter on [`get_symbolic_constraints`] and
//! [`get_max_constraint_degree`].

mod symbolic_builder;
mod symbolic_expression;
mod symbolic_variable;

pub use symbolic_builder::*;
pub use symbolic_expression::*;
pub use symbolic_variable::*;
