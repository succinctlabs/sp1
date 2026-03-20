use serde::de::DeserializeOwned;
use serde::Serialize;
use slop_algebra::{Dorroh, TwoAdicField};
use slop_challenger::{FieldChallenger, IopCtx};
use slop_multilinear::Point;

use crate::compiler::{ConstraintCtx, ReadingCtx, TranscriptExhaustedError};
use crate::zk::inner::{
    ConstraintContextInnerExt, ExpressionIndex, MleCommitmentIndex, ZkCnstrAndReadingCtxInner,
    ZkPcsVerifier, ZkVerificationContext, ZkVerifierError,
};
use crate::zk::ZkProof;

/// Extension of [`IopCtx`] for IOP contexts that can be used with VEIL.
///
/// Currently, we simply limit this to hash based IOPs using Reed-Solomon encoding. Future
/// implementation can expend to other codes.
///
/// The `PcsProof` associated type identifies the proof type produced by the PCS scheme
/// used with this context.
pub trait ZkIopCtx: IopCtx<F: TwoAdicField, EF: TwoAdicField> {
    /// The PCS proof type for this context.
    type PcsProof: Clone + Serialize + DeserializeOwned;

    type PcsVerifier: ZkPcsVerifier<Self, Proof = Self::PcsProof>;
}

pub struct ZkVerifierCtx<GC: ZkIopCtx> {
    inner: ZkVerificationContext<GC>,
    pcs_verifier: Option<GC::PcsVerifier>,
}

impl<GC: ZkIopCtx> ZkVerifierCtx<GC> {
    pub fn init(proof: ZkProof<GC>, pcs_verifier: Option<GC::PcsVerifier>) -> Self {
        let inner = proof.open();
        Self { inner, pcs_verifier }
    }

    /// Verify after consuming the transcript and building all constraints
    pub fn verify(self) -> Result<(), ZkVerifierError> {
        self.inner.verify(self.pcs_verifier.as_ref())
    }
}

/// An abstract representation of a transcript extension field element.
///
/// Either a concrete field constant (`Dorroh::Constant`) or an opaque expression index
/// into the verifier transcript (`Dorroh::Element`).
#[allow(type_alias_bounds)]
pub type TranscriptElement<GC: ZkIopCtx> =
    Dorroh<GC::EF, ExpressionIndex<GC::EF, ZkVerificationContext<GC>>>;

pub struct MleCommit {
    pub(crate) inner: MleCommitmentIndex,
}

// ============================================================================
// Conversion helper: HiddenElement → VerifierValue
// ============================================================================

fn into_verifier_value<GC: ZkIopCtx>(
    elem: TranscriptElement<GC>,
    ctx: &mut ZkVerificationContext<GC>,
) -> ExpressionIndex<GC::EF, ZkVerificationContext<GC>> {
    match elem {
        Dorroh::Constant(f) => ctx.cst(f),
        Dorroh::Element(e) => e,
    }
}

// ============================================================================
// ConstraintCtx impl
// ============================================================================

impl<GC: ZkIopCtx> ConstraintCtx for ZkVerifierCtx<GC> {
    type Field = GC::F;
    type Extension = GC::EF;
    type Expr = TranscriptElement<GC>;
    type Challenge = GC::EF;
    type MleOracle = MleCommit;

    fn assert_zero(&mut self, expr: TranscriptElement<GC>) {
        let idx = into_verifier_value(expr, &mut self.inner);
        self.inner.assert_zero(idx);
    }

    fn assert_a_times_b_equals_c(
        &mut self,
        a: TranscriptElement<GC>,
        b: TranscriptElement<GC>,
        c: TranscriptElement<GC>,
    ) {
        let ai = into_verifier_value(a, &mut self.inner);
        let bi = into_verifier_value(b, &mut self.inner);
        let ci = into_verifier_value(c, &mut self.inner);
        self.inner.assert_a_times_b_equals_c(ai, bi, ci);
    }

    fn assert_mle_multi_eval(
        &mut self,
        claims: Vec<(MleCommit, TranscriptElement<GC>)>,
        point: Point<GC::EF>,
    ) {
        let inner_claims: Vec<_> = claims
            .into_iter()
            .map(|(oracle, eval_expr)| {
                let eval_idx = into_verifier_value(eval_expr, &mut self.inner);
                (oracle.inner, eval_idx)
            })
            .collect();
        self.inner.assert_mle_multi_eval(inner_claims, point);
    }
}

// ============================================================================
// ReadingCtx impl
// ============================================================================

impl<GC: ZkIopCtx> ReadingCtx for ZkVerifierCtx<GC> {
    fn read_exact(&mut self, buf: &mut [Self::Expr]) -> Result<(), TranscriptExhaustedError> {
        // If we only want one element, use a more efficient method that avoids allocations.
        if buf.len() == 1 {
            buf[0] =
                self.inner.read_one().map(Dorroh::Element).ok_or(TranscriptExhaustedError(1))?;
            return Ok(());
        }
        // Otherwise, read a vector and copy.
        let values = self.inner.read_next(buf.len()).ok_or(TranscriptExhaustedError(buf.len()))?;
        for (b, value) in buf.iter_mut().zip(values) {
            *b = Dorroh::Element(value);
        }
        Ok(())
    }

    fn read_oracle(&mut self, log_width: u32, log_stacking: u32) -> Option<MleCommit> {
        self.inner
            .read_next_pcs_commitment(log_width as usize, log_stacking as usize)
            .map(|idx| MleCommit { inner: idx })
    }

    fn sample(&mut self) -> GC::EF {
        self.inner.challenger().sample_ext_element()
    }
}
