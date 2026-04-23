//! Backend-agnostic integration tests for veil protocols.
//!
//! [`abstract_sumcheck_flows`] contains one `*_prover` + one `*_verifier` per test
//! scenario, generic over `SendingCtx` / `ReadingCtx`. [`zk`] and
//! [`transparent`] are thin facades that wire concrete prover / verifier
//! contexts to those flows and host the actual `#[test]` entry points.
//!
//! Scenarios compose directly on top of [`crate::protocols`] (sumcheck, etc.)
//! and the primitive `assert_mle_eval` / `commit_mle` surface — there is no
//! intermediate per-role helper layer. Any genuine cross-scenario primitives
//! (e.g. a shared "commit MLE at the standard PCS shape" helper) can land in
//! their own module here once two or more scenarios need them.

pub mod abstract_sumcheck_flows;
mod transparent;
mod zk;
