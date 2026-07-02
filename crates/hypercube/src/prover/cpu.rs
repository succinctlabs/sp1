use slop_algebra::extension::BinomialExtensionField;
use slop_basefold_prover::BasefoldProver;
use slop_challenger::IopCtx;
use slop_jagged::{DefaultJaggedProver, JaggedProver};
use slop_multilinear::BatchPcsVerifier;
use sp1_primitives::{SP1Field, SP1GlobalContext};

use super::{DefaultTraceGenerator, ShardProver, SimpleProver, ZerocheckAir};
use crate::{
    prover::SP1MerkleTreeProver, GkrProverImpl, InnerSC, LogupGkrCpuTraceGenerator, SP1Pcs,
    ShardContextImpl, ShardVerifier,
};

type SC<GC, Verifier, A> = ShardContextImpl<GC, Verifier, A>;

/// A CPU shard prover.
pub type CpuShardProver<GC, Verifier, PcsComponents, A> =
    ShardProver<GC, SC<GC, Verifier, A>, PcsComponents>;

/// A CPU simple prover.
pub type CpuSimpleProver<GC, Verifier, PcsComponents, A> =
    SimpleProver<GC, SC<GC, Verifier, A>, CpuShardProver<GC, Verifier, PcsComponents, A>>;

impl<GC, Verifier, A, PcsComponents> CpuShardProver<GC, Verifier, PcsComponents, A>
where
    GC: IopCtx,
    Verifier: BatchPcsVerifier<GC>,
    PcsComponents: DefaultJaggedProver<GC, Verifier>,
    A: ZerocheckAir<GC::F, GC::EF>,
{
    /// Create a new CPU prover.
    #[must_use]
    pub fn new(verifier: ShardVerifier<GC, ShardContextImpl<GC, Verifier, A>>) -> Self {
        // Construct the shard prover.
        let ShardVerifier { jagged_pcs_verifier: pcs_verifier, machine } = verifier;
        let pcs_prover = JaggedProver::from_verifier(&pcs_verifier);
        let trace_generator = DefaultTraceGenerator::new(machine);
        let logup_gkr_trace_generator = LogupGkrCpuTraceGenerator::default();
        let logup_gkr_prover = GkrProverImpl::new(logup_gkr_trace_generator);

        Self::from_components(trace_generator, logup_gkr_prover, pcs_prover)
    }
}

/// Create a [`SimpleProver`] from a verifier with a single permit.
///
/// This is the recommended way to create a prover for tests and development.
#[must_use]
pub fn simple_prover<A>(
    verifier: ShardVerifier<SP1GlobalContext, InnerSC<A>>,
) -> CpuSimpleProver<
    SP1GlobalContext,
    SP1Pcs<SP1GlobalContext>,
    BasefoldProver<SP1GlobalContext, SP1MerkleTreeProver>,
    A,
>
where
    A: ZerocheckAir<SP1Field, BinomialExtensionField<SP1Field, 4>>,
{
    let shard_prover = CpuShardProver::new(verifier.clone());
    SimpleProver::new(verifier, shard_prover)
}
