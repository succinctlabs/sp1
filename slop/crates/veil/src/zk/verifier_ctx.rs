use serde::de::DeserializeOwned;
use serde::Serialize;
use slop_algebra::{Dorroh, TwoAdicField};
use slop_challenger::IopCtx;

use crate::compiler::ConstraintCtx;
use crate::zk::inner::{ExpressionIndex, MleCommitmentIndex, ZkVerificationContext};

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
}

pub struct ZkVerifierCtx<GC: ZkIopCtx> {
    inner: ZkVerificationContext<GC>,
}

/// An abstract representation of a transcript extension field element.
pub struct HiddenElement<GC: ZkIopCtx> {
    inner: Dorroh<GC::EF, ExpressionIndex<GC::EF, ZkVerificationContext<GC>>>,
}

pub struct MleCommit {
    inner: MleCommitmentIndex,
}

impl<GC: ZkIopCtx> ConstraintCtx for ZkVerifierCtx<GC> {
    type Field = GC::F;
    type Extension = GC::EF;

    type Expr = Dorroh<GC::EF, ExpressionIndex<GC::EF, ZkVerificationContext<GC>>>;
    type MleOracle = MleCommit;
}
