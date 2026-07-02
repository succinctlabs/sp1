//! Basefold wiring for the (base-PCS-generic) ZK stacked PCS.
//!
//! Everything in this module is specific to using Basefold as the base PCS: the [`Sealed`] opt-in
//! for [`StackedPcsProver`] (which is the base PCS directly — no wrapper), the [`ZkBasefoldVerifier`]
//! alias instantiating [`ZkStackedVerifier`] with [`StackedPcsVerifier`] (Basefold pinned to its
//! stacking height), and the prover-context configuration glue. The generic protocol — including
//! the blanket [`crate::zk::inner::ZkPcsProver`] impl and [`ZkStackedVerifier`]'s
//! [`crate::zk::inner::ZkPcsVerifier`] impl — lives in [`super::prover`] and [`super::verifier`],
//! which know nothing about Basefold.
//!
//! Every base-PCS / merkleizer type here is keyed to the *bare* context [`ZkIopCtx::Ctx`], not the
//! ZK bundle `GC`: the commitment scheme and base PCS depend only on the crypto config, so the
//! stock merkleizer is reused across PCS choices. Only the transcript/wire-format glue stays on
//! `GC`.

use super::sealed::Sealed;
use super::{ZkStackedPcsProof, ZkStackedPcsProverData, ZkStackedVerifier};
use crate::zk::inner::{MerkleProverData, ProverValue, ZkIopCtx, ZkMerkleizer, ZkProverContext};
use crate::zk::prover_ctx::{PcsProverConfig, ZkProverCtx};
use rand::distributions::{Distribution, Standard};
use rand::{CryptoRng, Rng};
use slop_basefold::{BasefoldProof, BasefoldVerifier};
use slop_basefold_prover::{BasefoldProver, BasefoldProverData};
use slop_challenger::IopCtx;
use std::marker::PhantomData;

/// Per-commitment prover data produced by the Basefold-backed ZK stacked PCS commit phase.
#[allow(type_alias_bounds)]
pub type BasefoldCommitData<GC: IopCtx, MK: ZkMerkleizer<GC>> =
    BasefoldProverData<GC::F, MerkleProverData<GC, MK>>;

/// The ZK stacked PCS proof when the base PCS is Basefold (its `rlc_eval_proof` is a Basefold
/// proof). This is the [`ZkPcsProver::Proof`](crate::zk::ZkPcsProver::Proof) of the Basefold-backed
/// stacked PCS.
#[allow(type_alias_bounds)]
pub type ZkStackedBasefoldProof<GC: IopCtx> = ZkStackedPcsProof<GC, BasefoldProof<GC>>;

/// The ZK stacked PCS verifier when the base PCS is Basefold: [`StackedPcsVerifier`] is the
/// Basefold verifier (over the bare ctx) pinned to its fixed stacking height (= `num_encoding_variables`).
#[allow(type_alias_bounds)]
pub type ZkBasefoldVerifier<GC: ZkIopCtx> = ZkStackedVerifier<GC, BasefoldVerifier<GC>>;

// Opt the Basefold prover into the blanket `ZkPcsProver` impl. The base PCS is the `BasefoldProver`
// directly — the ZK commit/prove logic reaches it purely through `BatchPcsProver` (the reduced-rate
// commit goes through `commit_mles_with_log_blowup`), so no wrapper is needed (mirroring the
// verifier side, where `ZkBasefoldVerifier` is just a type alias).
impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> Sealed for BasefoldProver<GC, MK> {}

/// Type alias for `ProverValue` when using the Basefold-backed ZK stacked PCS.
///
/// This is the expression index type that should be used by downstream code
/// (e.g., zk-sumcheck) when working with the ZK PCS prover context.
#[allow(type_alias_bounds)]
pub type StackedPcsProverValue<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> =
    ProverValue<GC, MK, ZkStackedPcsProverData<GC, BasefoldCommitData<GC, MK>>>;

/// Type alias for `ZkProverContext` when using the Basefold-backed ZK stacked PCS.
///
/// This is the prover context type that should be used by downstream code
/// (e.g., zk-sumcheck) when working with the ZK PCS.
#[allow(type_alias_bounds)]
pub type StackedPcsZkProverContext<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> =
    ZkProverContext<GC, MK, ZkStackedPcsProverData<GC, BasefoldCommitData<GC, MK>>>;

/// Configuration type that implements `PcsProverConfig` for the Basefold-backed stacked PCS.
pub struct StackedPcsProverConfig<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> {
    _phantom: PhantomData<(GC, MK)>,
}

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> PcsProverConfig<GC> for StackedPcsProverConfig<GC, MK> {
    type Merkelizer = MK;
    type PcsProver = BasefoldProver<GC, MK>;
}

/// Type alias for `ZkProverCtx` when using the Basefold-backed stacked PCS.
#[allow(type_alias_bounds)]
pub type StackedPcsZkProverCtx<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> =
    ZkProverCtx<GC, StackedPcsProverConfig<GC, MK>>;

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> ZkProverCtx<GC, StackedPcsProverConfig<GC, MK>> {
    /// Initializes a prover context with stacked PCS support.
    pub fn initialize_with_pcs<RNG: CryptoRng + Rng>(
        mask_length: usize,
        pcs_prover: BasefoldProver<GC, MK>,
        rng: &mut RNG,
    ) -> Result<Self, crate::zk::ZkProverCtxInitError<GC, StackedPcsProverConfig<GC, MK>>>
    where
        Standard: Distribution<GC::EF>,
    {
        Self::initialize(mask_length, rng, Some(pcs_prover))
    }

    /// Initializes a linear-only prover context with stacked PCS support.
    pub fn initialize_with_pcs_only_lin<RNG: CryptoRng + Rng>(
        mask_length: usize,
        pcs_prover: BasefoldProver<GC, MK>,
        rng: &mut RNG,
    ) -> Result<Self, crate::zk::ZkProverCtxInitError<GC, StackedPcsProverConfig<GC, MK>>>
    where
        Standard: Distribution<GC::EF>,
    {
        Self::initialize_only_lin_constraints(mask_length, rng, Some(pcs_prover))
    }
}
