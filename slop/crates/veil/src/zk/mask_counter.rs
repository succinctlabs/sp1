use slop_algebra::Dorroh;
use slop_challenger::FieldChallenger;

use crate::compiler::{ConstraintCtx, ReadingCtx, TranscriptExhaustedError};
use crate::zk::inner::MaskCounterContext;
use crate::zk::verifier_ctx::MleCommit;
use crate::zk::ZkIopCtx;

/// Expression type for the mask counter — a dummy that just counts transcript reads.
#[allow(type_alias_bounds)]
pub type MaskCounterExpr<GC: ZkIopCtx> = Dorroh<GC::EF, MaskCounterContext<GC>>;

/// A counting context for determining the mask length needed by a ZK proof.
///
/// Implements `ReadingCtx` + `ConstraintCtx` so it can be used with the public interface
/// (compiler sumcheck, etc.) to count how many transcript elements will be read.
pub struct MaskCounter<GC: ZkIopCtx> {
    inner: MaskCounterContext<GC>,
}

impl<GC: ZkIopCtx> Default for MaskCounter<GC> {
    fn default() -> Self {
        Self { inner: MaskCounterContext::default() }
    }
}

impl<GC: ZkIopCtx> MaskCounter<GC> {
    fn count(&self) -> usize {
        self.inner.count()
    }
}

/// Computes the mask length by running the protocol's read and constraint
/// building logic on a counting context.
///
/// # Arguments
/// * `read_all` - Reads proof data from the context (mirrors prover's transcript writes)
/// * `build_all` - Builds constraints using the read data
pub fn compute_mask_length<GC, T>(
    read_all: impl FnOnce(&mut MaskCounter<GC>) -> T,
    build_all: impl FnOnce(T, &mut MaskCounter<GC>),
) -> usize
where
    GC: ZkIopCtx,
{
    let mut counter = MaskCounter::<GC>::default();
    let data = read_all(&mut counter);
    build_all(data, &mut counter);
    counter.count()
}

// ============================================================================
// ConstraintCtx impl
// ============================================================================

impl<GC: ZkIopCtx> ConstraintCtx for MaskCounter<GC> {
    type Field = GC::F;
    type Extension = GC::EF;
    type Expr = MaskCounterExpr<GC>;
    type MleOracle = MleCommit;

    fn assert_zero(&mut self, _expr: Self::Expr) {}

    fn assert_a_times_b_equals_c(&mut self, _a: Self::Expr, _b: Self::Expr, _c: Self::Expr) {}

    fn assert_mle_eval(
        &mut self,
        oracle: MleCommit,
        _point: slop_multilinear::Point<Self::Expr>,
        _eval_expr: Self::Expr,
    ) {
        use crate::zk::inner::ConstraintContextInnerExt;
        // Delegate to inner which knows how to count PCS verification reads
        self.inner.assert_mle_eval(
            oracle.inner,
            slop_multilinear::Point::default(),
            self.inner.clone(),
        );
    }
}

// ============================================================================
// ReadingCtx impl
// ============================================================================

impl<GC: ZkIopCtx> ReadingCtx for MaskCounter<GC> {
    fn read_exact(&mut self, buf: &mut [Self::Expr]) -> Result<(), TranscriptExhaustedError> {
        use crate::zk::inner::ZkCnstrAndReadingCtxInner;
        let values = self.inner.read_next(buf.len()).ok_or(TranscriptExhaustedError(buf.len()))?;
        for (b, v) in buf.iter_mut().zip(values) {
            *b = Dorroh::Element(v);
        }
        Ok(())
    }

    fn read_oracle(&mut self, log_width: usize, log_stacking: usize) -> Option<MleCommit> {
        use crate::zk::inner::ZkCnstrAndReadingCtxInner;
        self.inner
            .read_next_pcs_commitment(log_width, log_stacking)
            .map(|idx| MleCommit { inner: idx })
    }

    fn sample(&mut self) -> Self::Expr {
        use crate::zk::inner::ZkCnstrAndReadingCtxInner;
        let f: GC::EF = self.inner.challenger().sample_ext_element();
        Dorroh::Constant(f)
    }
}
