//! Direct R1CS compilation backend for Symphony/LatticeFold integration.
//!
//! This module compiles SP1's recursion IR (`DslIr`) directly to R1CS matrices,
//! avoiding the JSON intermediate representation used by the gnark backend.
//!
//! The R1CS format is: for each constraint row i,
//!   (A[i] · w) * (B[i] · w) = (C[i] · w)
//! where w is the witness vector (including constants and public inputs).

pub mod types;
pub mod compiler;
pub mod babybear;
pub mod poseidon2;

#[cfg(test)]
mod tests;

pub use types::*;
pub use compiler::R1CSCompiler;
