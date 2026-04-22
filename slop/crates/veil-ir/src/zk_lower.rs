//! ZK verifier lowering (stub for PR1).
//!
//! Replays a [`Program`] against any implementation of
//! `slop_veil::compiler::ConstraintCtx` + `ReadingCtx`, producing the same
//! side effects as if the verifier function had been invoked directly on
//! that context. With `C = slop_veil::zk::ZkVerifierCtx`, this is the ZK
//! backend lowering.
//!
//! # Status
//!
//! PR1 lands the public signature and the statement-dispatch skeleton. The
//! expression-lowering body uses [`crate::walk_expr_dag`] with
//! `T = C::Expr`, but constructing `C::Expr` values for constants requires
//! `AbstractField` calls on the context's `Expr` type, which is
//! straightforward in principle but needs a concrete equivalence test against
//! `SumcheckParam::read` + `ZkVerifierCtx` to be meaningful. That test is
//! the deliverable of PR2, which will fill in the body below. For PR1 we
//! leave the walker unimplemented so the crate compiles cleanly and any
//! future caller sees an explicit "not yet supported" error rather than
//! silently producing a wrong result.

use std::hash::Hash;

use slop_algebra::{AbstractField, ExtensionField, Field};
use slop_veil::compiler::ReadingCtx;
use thiserror::Error;

use crate::{Program, Stmt};

#[derive(Debug, Error)]
pub enum LowerError {
    #[error("transcript exhausted during replay")]
    TranscriptExhausted(#[from] slop_veil::compiler::TranscriptExhaustedError),
    #[error("the context could not produce an oracle for ReadOracle #{stmt_idx}")]
    OracleUnavailable { stmt_idx: usize },
    #[error("ZK lowering is not fully implemented in PR1; see crate::zk_lower docs")]
    NotImplemented,
}

/// Replay a [`Program`] against `ctx`. See module docs for status.
#[allow(clippy::needless_pass_by_ref_mut, clippy::result_large_err)]
pub fn zk_lower_verifier<F, E, C>(program: &Program<E>, _ctx: &mut C) -> Result<(), LowerError>
where
    F: Field,
    E: ExtensionField<F> + Hash + Eq,
    C: ReadingCtx<Field = F, Extension = E>,
    C::Expr: AbstractField,
{
    // Skeleton only. Real implementation walks stmts and lowers expressions
    // via `walk_expr_dag` with `T = C::Expr`. Deferred to PR2 per module
    // docs.
    if !program.stmts.is_empty() {
        return Err(LowerError::NotImplemented);
    }
    let _ = |_: &Stmt| {};
    Ok(())
}
