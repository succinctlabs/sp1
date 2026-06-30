pub mod sumcheck;

use thiserror::Error;

use crate::compiler::TranscriptReadError;
use crate::protocols::sumcheck::SumcheckError;

/// Error returned by a unified read-and-constrain "verify" body (the function both the verifier
/// and the replaying prover run against a [`ReadingCtx`](crate::compiler::ReadingCtx)).
///
/// It aggregates the failure modes such a body encounters so they can be propagated with `?`
/// instead of unwrapped:
/// - reading proof values from the transcript ([`TranscriptReadError`]),
/// - reading a committed MLE oracle (none available → [`Self::MissingOracle`]),
/// - errors for library protocols(currently just [`SumcheckError`]),
/// - the constraint / eager-PCS assertions, whose error type `A` is the context's
///   [`ConstraintCtx::AssertError`](crate::compiler::ConstraintCtx::AssertError).
#[derive(Debug, Error)]
pub enum ProtocolError<A: std::error::Error> {
    /// Reading a value from the proof transcript failed.
    #[error(transparent)]
    Transcript(#[from] TranscriptReadError),
    /// An MLE oracle was expected in the transcript but none was available.
    #[error("expected a committed MLE oracle but none was available in the transcript")]
    MissingOracle,
    /// A constraint assertion (including an eager PCS opening) failed.
    #[error("assertion failed: {0}")]
    Assert(A),
    // Errors for library protocols:
    /// The inner sumcheck failed to verify.
    #[error(transparent)]
    Sumcheck(#[from] SumcheckError),
}
