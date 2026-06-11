//! The seam for deriving the global `LogUp` challenge pair.
//!
//! The global-scope interactions of all chunks share one `(alpha_global, betas_global)` pair, so
//! that the exposed per-shard global cumulative sums cancel across shards. The derivation of that
//! pair from public cross-chunk data is user-owned and lands later; this module fixes the
//! *position* of the derivation in the transcript (after the global commitment is observed,
//! before the main commitment) and provides a stub that samples from the challenger.

use std::{marker::PhantomData, sync::Arc};

use slop_algebra::Field;
use slop_challenger::{FieldChallenger, IopCtx};
use slop_multilinear::Point;

use crate::{air::InteractionScope, air::MachineAir, Chip, MachineRecord};

/// The public data from which the global challenge pair is derived.
///
/// TBD: chunk global commitments and any other cross-chunk public data the real derivation
/// needs. The stub derivation ignores it.
#[derive(Debug, Clone)]
pub struct GlobalProvingInput<GC: IopCtx> {
    _marker: PhantomData<GC>,
}

impl<GC: IopCtx> Default for GlobalProvingInput<GC> {
    fn default() -> Self {
        Self { _marker: PhantomData }
    }
}

/// A source for the global `LogUp` challenge pair `(alpha_global, beta_seed_global)`.
pub trait GlobalChallengeSource<GC: IopCtx>: Send + Sync {
    /// Derive the global challenge pair.
    ///
    /// MUST be a pure function of public data + transcript; the prover and the verifier call it
    /// at the same transcript position with the same inputs.
    fn derive(
        &self,
        input: &GlobalProvingInput<GC>,
        beta_seed_dim: u32,
        challenger: &mut GC::Challenger,
    ) -> (GC::EF, Point<GC::EF>);
}

/// The stub [`GlobalChallengeSource`] until the real cross-chunk derivation lands: samples the
/// pair from the challenger.
#[derive(Debug, Clone, Copy, Default)]
pub struct SampleFromChallenger;

impl<GC: IopCtx> GlobalChallengeSource<GC> for SampleFromChallenger {
    fn derive(
        &self,
        _input: &GlobalProvingInput<GC>,
        beta_seed_dim: u32,
        challenger: &mut GC::Challenger,
    ) -> (GC::EF, Point<GC::EF>) {
        let alpha = challenger.sample_ext_element::<GC::EF>();
        let beta_seed = (0..beta_seed_dim)
            .map(|_| challenger.sample_ext_element::<GC::EF>())
            .collect::<Point<_>>();
        (alpha, beta_seed)
    }
}

/// The `(input, source)` pair threaded through the provers and the verifier.
#[derive(Clone)]
pub struct GlobalChallengeSeam<GC: IopCtx> {
    /// The public data the derivation reads.
    pub input: GlobalProvingInput<GC>,
    /// The derivation itself.
    pub source: Arc<dyn GlobalChallengeSource<GC>>,
}

impl<GC: IopCtx> GlobalChallengeSeam<GC> {
    /// Create a seam from its parts.
    #[must_use]
    pub fn new(input: GlobalProvingInput<GC>, source: Arc<dyn GlobalChallengeSource<GC>>) -> Self {
        Self { input, source }
    }

    /// The stub seam: sample the pair from the challenger.
    #[must_use]
    pub fn stub() -> Self {
        Self::new(GlobalProvingInput::default(), Arc::new(SampleFromChallenger))
    }

    /// Derive the global challenge pair.
    pub fn derive(
        &self,
        beta_seed_dim: u32,
        challenger: &mut GC::Challenger,
    ) -> (GC::EF, Point<GC::EF>) {
        self.source.derive(&self.input, beta_seed_dim, challenger)
    }
}

impl<GC: IopCtx> Default for GlobalChallengeSeam<GC> {
    fn default() -> Self {
        Self::stub()
    }
}

/// The maximum fingerprint arity over the public-value interactions of record type `R`: the
/// number of values sent plus one for the interaction kind.
#[must_use]
pub fn pv_interaction_max_arity<R: MachineRecord>() -> usize {
    R::interactions_in_public_values().iter().map(|kind| kind.num_values() + 1).max().unwrap_or(1)
}

/// The beta-seed dimension for the challenge pair of `scope`: covers every interaction of that
/// scope among `chips`, plus the public-value interaction kinds (`pv_max_arity`, computed via
/// [`pv_interaction_max_arity`]).
///
/// The local pair covers the chips of the shard; the global pair must be shard-independent, so
/// its dimension is computed over all chips of the machine.
pub fn beta_seed_dim_for_scope<'a, F: Field, A: MachineAir<F> + 'a>(
    chips: impl IntoIterator<Item = &'a Chip<F, A>>,
    scope: InteractionScope,
    pv_max_arity: usize,
) -> u32 {
    chips
        .into_iter()
        .flat_map(|chip| chip.sends().iter().chain(chip.receives().iter()))
        .filter(|interaction| interaction.scope == scope)
        .map(|interaction| interaction.values.len() + 1)
        .chain(std::iter::once(pv_max_arity))
        .max()
        .unwrap()
        .next_power_of_two()
        .ilog2()
}
