//! Library surface of the constraint-compiler crate.
//!
//! The extraction driver itself stays in `src/main.rs`; this library exposes the
//! conformance substrate (deterministic event batteries + real `generate_trace`
//! row extraction + the dump schema) so the `chip_traces` binary and the
//! `witgen_conformance` integration test share one implementation.

pub mod conformance;
