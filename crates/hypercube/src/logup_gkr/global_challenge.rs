//! Deriving the global `LogUp` challenge pair.

use slop_algebra::Field;
use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
use slop_multilinear::Point;
use slop_symmetric::CryptographicHasher;

use crate::{air::InteractionScope, air::MachineAir, Chip, MachineRecord};

/// Derive the chunk's shared global `LogUp` challenge pair `(alpha_global, beta_seed_global)`.
pub fn observe_global_challenge<GC: IopCtx>(
    commitments: Option<&[GC::Digest]>,
    beta_seed_dim: u32,
    challenger: &mut GC::Challenger,
) -> (GC::EF, Point<GC::EF>) {
    if let Some(commitments) = commitments {
        let (hasher, _) = GC::default_hasher_and_compressor();
        challenger.observe(hasher.hash_iter(commitments.iter().flat_map(GC::digest_to_elements)));
    }
    let alpha = challenger.sample_ext_element::<GC::EF>();
    let beta_seed =
        (0..beta_seed_dim).map(|_| challenger.sample_ext_element::<GC::EF>()).collect::<Point<_>>();
    (alpha, beta_seed)
}

/// The maximum fingerprint arity over the public-value interactions of record type `R`.
#[must_use]
pub fn pv_interaction_max_arity<R: MachineRecord>() -> usize {
    R::interactions_in_public_values().iter().map(|kind| kind.num_values() + 1).max().unwrap_or(1)
}

/// The beta-seed dimension for the challenge pair of `scope`.
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

#[cfg(test)]
mod tests {
    use slop_algebra::AbstractField;
    use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
    use slop_multilinear::Point;
    use slop_symmetric::CryptographicHasher;
    use sp1_primitives::{SP1Field, SP1GlobalContext};

    use super::observe_global_challenge;

    type GC = SP1GlobalContext;
    type EF = <GC as IopCtx>::EF;
    type Digest = <GC as IopCtx>::Digest;

    /// A distinct digest per index.
    fn leaf(x: u32) -> Digest {
        std::array::from_fn(|i| SP1Field::from_canonical_u32(x * 8 + i as u32 + 1))
    }

    /// The challenge pair from observing `digest` then sampling, as the tail of
    /// `observe_global_challenge` after it folds the commitments.
    fn challenge_from_observed_digest(digest: Digest, beta_seed_dim: u32) -> (EF, Point<EF>) {
        let mut challenger = GC::default_challenger();
        challenger.observe(digest);
        let alpha = challenger.sample_ext_element::<EF>();
        let beta_seed =
            (0..beta_seed_dim).map(|_| challenger.sample_ext_element::<EF>()).collect::<Point<_>>();
        (alpha, beta_seed)
    }

    /// The commitments are folded into a single `hash_iter` over their elements concatenated in
    /// order with no length prefix, and that one digest is observed.
    #[test]
    fn observes_hash_iter_of_commitment_elements() {
        let commitments: [Digest; 3] = std::array::from_fn(|i| leaf(i as u32));
        let beta_seed_dim = 2;

        let (hasher, _) = GC::default_hasher_and_compressor();
        let elements: Vec<SP1Field> = commitments.iter().flatten().copied().collect();
        let expected = challenge_from_observed_digest(hasher.hash_iter(elements), beta_seed_dim);

        let mut challenger = GC::default_challenger();
        let got =
            observe_global_challenge::<GC>(Some(&commitments), beta_seed_dim, &mut challenger);
        assert_eq!(got, expected);

        // The fold is order-dependent: reordering the commitments changes the challenge.
        let reordered = [commitments[2], commitments[0], commitments[1]];
        let mut challenger = GC::default_challenger();
        let got_reordered =
            observe_global_challenge::<GC>(Some(&reordered), beta_seed_dim, &mut challenger);
        assert_ne!(got, got_reordered);
    }
}
