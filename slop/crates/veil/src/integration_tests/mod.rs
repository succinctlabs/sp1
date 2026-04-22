//! Backend-agnostic integration tests for veil protocols.
//!
//! [`examples`] contains one `*_prover` + one `*_verifier` per test scenario,
//! generic over `SendingCtx` / `ReadingCtx`. Each backend's `tests.rs` is a
//! thin facade that wires concrete prover / verifier contexts to those flows.
//!
//! Scenarios compose directly on top of [`crate::protocols`] (sumcheck, etc.)
//! and the primitive `assert_mle_eval` / `commit_mle` surface — there is no
//! intermediate per-role helper layer. Any genuine cross-scenario primitives
//! (e.g. a shared "commit MLE at the standard PCS shape" helper) can land in
//! their own module here once two or more scenarios need them.

pub mod examples;
