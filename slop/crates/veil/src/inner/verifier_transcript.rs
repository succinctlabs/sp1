use slop_algebra::AbstractField;

use super::{
    ExpressionIndex, TranscriptIndex, TranscriptLinConstraint, ZkElement, ZkExpression, ZkIopCtx,
    ZkLinExpression, ZkVerificationContext,
};

pub type VerifierElement<K> = TranscriptIndex<K>;

pub type VerifierLinExpression<K> = TranscriptLinConstraint<K>;

impl<K: AbstractField + Copy> ZkElement<K> for VerifierElement<K> {
    type LinExpr = VerifierLinExpression<K>;
}

impl<K: AbstractField + Copy> ZkLinExpression<K, VerifierElement<K>> for VerifierLinExpression<K> {}

impl<K: AbstractField + Copy> From<[usize; 2]> for ZkExpression<K, VerifierElement<K>> {
    fn from(indices: [usize; 2]) -> Self {
        let elt: VerifierElement<K> = indices.into();
        ZkExpression::Element(elt)
    }
}

/// Type alias for expression indices in the verifier context.
///
/// # Type Parameters
/// * `GC` - The ZK IOP context type
/// * `PcsProof` - The PCS proof type (defaults to `()` when no PCS is used)
#[allow(type_alias_bounds)]
pub type VerifierValue<GC: ZkIopCtx, PcsProof = ()> =
    ExpressionIndex<GC::EF, ZkVerificationContext<GC, PcsProof>>;
