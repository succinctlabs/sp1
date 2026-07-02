use derive_where::derive_where;
use slop_algebra::{PrimeField32, TwoAdicField};
use slop_basefold::FriConfig;
use slop_challenger::IopCtx;

use serde::{Deserialize, Serialize};
use slop_multilinear::BatchPcsVerifier;
use sp1_primitives::{SP1GlobalContext, SP1OuterGlobalContext};
use thiserror::Error;

use crate::{
    prover::{CoreProofShape, PcsProof, ZerocheckAir},
    Machine, SP1Pcs, ShardVerifierConfigError,
};

use super::{MachineVerifyingKey, ShardProof, ShardVerifier, ShardVerifierError};
/// A complete proof of program execution.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "PcsProof: Serialize, GC::Challenger: Serialize",
    deserialize = "PcsProof: Deserialize<'de>, GC::Challenger: Deserialize<'de>"
))]
pub struct MachineProof<GC: IopCtx, PcsProof> {
    /// The shard proofs.
    pub shard_proofs: Vec<ShardProof<GC, PcsProof>>,
}

impl<GC: IopCtx, C> From<Vec<ShardProof<GC, C>>> for MachineProof<GC, C> {
    fn from(shard_proofs: Vec<ShardProof<GC, C>>) -> Self {
        Self { shard_proofs }
    }
}

/// A shortcut trait to package a multilinear PCS verifier and a zerocheck AIR. Reduces number of
/// generic parameters in the `MachineVerifier` type and `AirProver` trait.
pub trait ShardContext<GC: IopCtx>: 'static + Send + Sync {
    /// The multilinear PCS verifier.
    type Config: BatchPcsVerifier<GC>;
    /// The AIR for which we'll be proving zerocheck.
    type Air: ZerocheckAir<GC::F, GC::EF>;
}

/// The canonical type implementing `ShardContext`.
pub struct ShardContextImpl<GC: IopCtx, Verifier, A>
where
    Verifier: BatchPcsVerifier<GC>,
    A: ZerocheckAir<GC::F, GC::EF>,
{
    _marker: std::marker::PhantomData<(GC, Verifier, A)>,
}
/// A type alias assuming `SP1Pcs` (stacked Basefold) as the PCS verifier, generic in the `IopCtx`
/// and the AIR.
pub type SP1SC<GC, A> = ShardContextImpl<GC, SP1Pcs<GC>, A>;

/// A type alias for the shard contexts used in all stages of SP1 proving except wrap. Generic only
/// in the AIR (allowing this SC to be used for the Risc-V and the recursion AIRs).
pub type InnerSC<A> = SP1SC<SP1GlobalContext, A>;

/// A type alias for the shard contexts used in the outer (wrap) stage of SP1 proving. Generic only
/// in the AIR.
pub type OuterSC<A> = SP1SC<SP1OuterGlobalContext, A>;

impl<GC: IopCtx, Verifier, A> ShardContext<GC> for ShardContextImpl<GC, Verifier, A>
where
    Verifier: BatchPcsVerifier<GC>,
    A: ZerocheckAir<GC::F, GC::EF>,
{
    type Config = Verifier;
    type Air = A;
}

/// An error that occurs during the verification of a machine proof.
#[derive(Debug, Error)]
pub enum MachineVerifierError<EF, PcsError> {
    /// An error that occurs during the verification of a shard proof.
    #[error("invalid shard proof: {0}")]
    InvalidShardProof(#[from] ShardVerifierError<EF, PcsError>),
    /// The public values are invalid
    #[error("invalid public values: {0}")]
    InvalidPublicValues(&'static str),
    /// There are too many shards.
    #[error("too many shards")]
    TooManyShards,
    /// Invalid verification key.
    #[error("invalid verification key")]
    InvalidVerificationKey,
    /// Verification key not initialized.
    #[error("verification key not initialized")]
    UninitializedVerificationKey,
    /// Empty proof.
    #[error("empty proof")]
    EmptyProof,
}

/// Derive the error type from the machine config.
pub type MachineVerifierConfigError<GC, C> =
    MachineVerifierError<<GC as IopCtx>::EF, <C as BatchPcsVerifier<GC>>::VerifierError>;

/// A verifier for a machine proof.
#[derive_where(Clone)]
pub struct MachineVerifier<GC: IopCtx, SC: ShardContext<GC>> {
    /// Shard proof verifier.
    shard_verifier: ShardVerifier<GC, SC>,
}

impl<GC: IopCtx, SC: ShardContext<GC>> MachineVerifier<GC, SC> {
    /// Create a new machine verifier.
    pub fn new(shard_verifier: ShardVerifier<GC, SC>) -> Self {
        Self { shard_verifier }
    }

    /// Get a new challenger.
    pub fn challenger(&self) -> GC::Challenger {
        self.shard_verifier.challenger()
    }

    /// Get the machine.
    pub fn machine(&self) -> &Machine<GC::F, SC::Air> {
        &self.shard_verifier.machine
    }

    /// Get the maximum log row count.
    pub fn max_log_row_count(&self) -> usize {
        self.shard_verifier.jagged_pcs_verifier.max_log_row_count
    }

    /// Get the log stacking height.
    #[must_use]
    #[inline]
    pub fn log_stacking_height(&self) -> u32 {
        self.shard_verifier.log_stacking_height()
    }

    /// Get the shape of a shard proof.
    pub fn shape_from_proof(
        &self,
        proof: &ShardProof<GC, PcsProof<GC, SC>>,
    ) -> CoreProofShape<GC::F, SC::Air> {
        self.shard_verifier.shape_from_proof(proof)
    }

    /// Get the shard verifier.
    #[must_use]
    #[inline]
    pub fn shard_verifier(&self) -> &ShardVerifier<GC, SC> {
        &self.shard_verifier
    }
}

impl<GC: IopCtx, SC: ShardContext<GC>> MachineVerifier<GC, SC>
where
    GC::F: PrimeField32,
{
    /// Verify the machine proof.
    pub fn verify(
        &self,
        vk: &MachineVerifyingKey<GC>,
        proof: &MachineProof<GC, PcsProof<GC, SC>>,
    ) -> Result<(), MachineVerifierConfigError<GC, SC::Config>>
where {
        let mut challenger = self.challenger();
        // Observe the verifying key.
        vk.observe_into(&mut challenger);

        // Verify the shard proofs.
        for (i, shard_proof) in proof.shard_proofs.iter().enumerate() {
            let mut challenger = challenger.clone();
            let span = tracing::debug_span!("verify shard", i).entered();
            self.verify_shard(vk, shard_proof, &mut challenger)
                .map_err(MachineVerifierError::InvalidShardProof)?;
            span.exit();
        }

        Ok(())
    }

    /// Verify a shard proof.
    pub fn verify_shard(
        &self,
        vk: &MachineVerifyingKey<GC>,
        proof: &ShardProof<GC, PcsProof<GC, SC>>,
        challenger: &mut GC::Challenger,
    ) -> Result<(), ShardVerifierConfigError<GC, SC::Config>>
where {
        self.shard_verifier.verify_shard(vk, proof, challenger)
    }
}

impl<GC: IopCtx, SC: ShardContext<GC, Config = SP1Pcs<GC>>> MachineVerifier<GC, SC>
where
    GC::F: TwoAdicField,
    GC::EF: TwoAdicField,
{
    /// Get the FRI config.
    #[must_use]
    #[inline]
    pub fn fri_config(&self) -> &FriConfig<GC::F> {
        &self
            .shard_verifier
            .jagged_pcs_verifier
            .stacked_pcs_verifier
            .inner_verifier
            .inner
            .fri_config
    }
}
