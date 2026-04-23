//! Transparent backend: runs protocols directly, without zero-knowledge compilation.
//!
//! The prover produces a plain transcript (sent extension-field messages and oracle
//! commitments) and the verifier re-derives Fiat-Shamir challenges from it, just as
//! the protocol specifies — no masking, no partial-ZK wrapper. MLE commits still go
//! through the stock stacked-basefold PCS. Useful as a debug/reference backend
//! against which the ZK backend's behaviour can be compared, and as the simplest
//! point of comparison when generating soundness statements.

mod prover;
mod verifier;

pub use prover::*;
pub use verifier::*;
