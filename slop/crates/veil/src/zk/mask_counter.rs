use slop_algebra::Dorroh;
use slop_challenger::FieldChallenger;
use slop_multilinear::OracleEval;

use crate::compiler::{ConstraintCtx, MleEvalClaim, ReadingCtx, TranscriptReadError};
use crate::zk::inner::{ConstraintContextInnerExt, MaskCounterContext};
use crate::zk::verifier_ctx::MleCommit;
use crate::zk::ZkIopCtx;

/// Expression type for the mask counter — a dummy that just counts transcript reads.
#[allow(type_alias_bounds)]
pub type MaskCounterExpr<GC: ZkIopCtx> = Dorroh<GC::EF, MaskCounterContext<GC>>;

/// A counting context for determining the mask length needed by a ZK proof.
///
/// Implements `ReadingCtx` + `SendingCtx` + `ConstraintCtx` so it can be used with the
/// public interface (compiler sumcheck, etc.) to count how many transcript elements will be used.
pub struct MaskCounter<GC: ZkIopCtx> {
    inner: MaskCounterContext<GC>,
    /// The PCS's fixed `num_encoding_variables`, used to recover `log_num_polynomials`
    /// from an oracle's total number of variables in [`ReadingCtx::read_oracle`].
    num_encoding_variables: u32,
    /// Set once any MLE-eval claim has been counted. Guards against further transcript reads,
    /// which would read past the (terminal) PCS openings.
    pcs_claim_made: bool,
}

impl<GC: ZkIopCtx> MaskCounter<GC> {
    /// Creates a mask counter for a PCS with the given fixed `num_encoding_variables`.
    pub fn new(num_encoding_variables: u32) -> Self {
        Self { inner: MaskCounterContext::default(), num_encoding_variables, pcs_claim_made: false }
    }

    fn count(&self) -> usize {
        self.inner.count()
    }
}

/// Computes the mask length by running the protocol's unified `verify` body on
/// a counting context. The counter tallies every transcript read and every
/// constraint emitted; the return matches the eventual `mask_length` the real
/// prover/verifier need.
///
/// # Arguments
/// * `num_encoding_variables` - the PCS's fixed encoding width, used to size oracle reads
/// * `verify_all` - The protocol's `verify` function (reads + constrains in one pass)
pub fn compute_mask_length<GC, E>(
    num_encoding_variables: u32,
    verify_all: impl FnOnce(&mut MaskCounter<GC>) -> Result<(), E>,
) -> usize
where
    GC: ZkIopCtx,
    E: std::fmt::Debug,
{
    let mut counter = MaskCounter::<GC>::new(num_encoding_variables);
    // Counting never fails (the mask counter's reads/asserts are infallible tallies), so any error
    // here indicates a bug in the verify body itself.
    verify_all(&mut counter).expect("mask-counting verify body should not error");
    counter.count()
}

// ============================================================================
// ConstraintCtx impl
// ============================================================================

impl<GC: ZkIopCtx> ConstraintCtx for MaskCounter<GC> {
    type Field = GC::F;
    type Extension = GC::EF;
    type Expr = MaskCounterExpr<GC>;
    type Challenge = GC::EF;
    type MleCommit = MleCommit;
    type AssertError = std::convert::Infallible;

    fn assert_zero(&mut self, _expr: Self::Expr) -> Result<(), Self::AssertError> {
        Ok(())
    }

    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(MleCommit, Self::Expr)>,
        _point: &slop_multilinear::Point<GC::EF>,
    ) -> Result<(), Self::AssertError> {
        self.pcs_claim_made = true;
        // Count the transcript elements the PCS opening will add for this batch.
        let commitment_indices: Vec<_> =
            claims.into_iter().map(|(oracle, _)| oracle.inner).collect();
        self.inner.count_mle_multi_eval(&commitment_indices);
        Ok(())
    }

    fn assert_mle_multi_eval_with_oracle<O: OracleEval<Self::Expr, Self::Expr>>(
        &mut self,
        claims: Vec<MleEvalClaim<MleCommit, Self::Expr, O>>,
        _point: &slop_multilinear::Point<GC::EF>,
    ) -> Result<(), Self::AssertError> {
        self.pcs_claim_made = true;
        // Mirror the real opening: all the claims' commitments (flattened in claim order) are
        // opened in one base PCS proof. A custom combiner doesn't change how many transcript
        // elements are read.
        let commitment_indices: Vec<_> =
            claims.iter().flat_map(|c| c.commits.iter().map(|commit| commit.inner)).collect();
        self.inner.count_mle_multi_eval(&commitment_indices);
        Ok(())
    }
}

// ============================================================================
// ReadingCtx impl
// ============================================================================

impl<GC: ZkIopCtx> ReadingCtx for MaskCounter<GC> {
    fn read_exact(&mut self, buf: &mut [Self::Expr]) -> Result<(), TranscriptReadError> {
        use crate::zk::inner::ZkCnstrAndReadingCtxInner;
        if self.pcs_claim_made {
            return Err(TranscriptReadError::ReadAfterPcsClaim);
        }
        let values = self.inner.read_next(buf.len())?;
        for (b, v) in buf.iter_mut().zip(values) {
            *b = Dorroh::Element(v);
        }
        Ok(())
    }

    fn read_oracle(&mut self, num_variables: u32) -> Option<MleCommit> {
        use crate::zk::inner::ZkCnstrAndReadingCtxInner;
        let log_num_polynomials = num_variables.checked_sub(self.num_encoding_variables)?;
        self.inner
            .read_next_pcs_commitment(
                self.num_encoding_variables as usize,
                log_num_polynomials as usize,
            )
            .map(|idx| MleCommit { inner: idx })
    }

    fn sample(&mut self) -> GC::EF {
        self.inner.with_challenger(|c| c.sample_ext_element())
    }
}
