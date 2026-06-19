//! Deriving the global `LogUp` challenge pair.

use slop_algebra::Field;
use slop_challenger::{CanObserve, FieldChallenger, IopCtx};
use slop_multilinear::Point;
use slop_symmetric::PseudoCompressionFunction;

use crate::{air::InteractionScope, air::MachineAir, Chip, MachineRecord};

/// Derive the chunk's shared global `LogUp` challenge pair `(alpha_global, beta_seed_global)`.
pub fn observe_global_challenge<GC: IopCtx>(
    commitments: Option<&[GC::Digest]>,
    beta_seed_dim: u32,
    challenger: &mut GC::Challenger,
) -> (GC::EF, Point<GC::EF>) {
    if let Some(commitments) = commitments {
        let (_, compressor) = GC::default_hasher_and_compressor();
        challenger.observe(compact_merkle_root::<GC>(commitments, &compressor));
    }
    let alpha = challenger.sample_ext_element::<GC::EF>();
    let beta_seed =
        (0..beta_seed_dim).map(|_| challenger.sample_ext_element::<GC::EF>()).collect::<Point<_>>();
    (alpha, beta_seed)
}

/// The compact Merkle root over an ordered list of commitments.
#[must_use]
pub fn compact_merkle_root<GC: IopCtx>(
    leaves: &[GC::Digest],
    compressor: &GC::Compressor,
) -> GC::Digest {
    assert!(!leaves.is_empty(), "compact_merkle_root requires at least one leaf");
    let mut layer = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < layer.len() {
            next.push(compressor.compress([layer[i], layer[i + 1]]));
            i += 2;
        }
        // Promote a lone trailing node to the next level unchanged.
        if i < layer.len() {
            next.push(layer[i]);
        }
        layer = next;
    }
    layer[0]
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
    use slop_challenger::IopCtx;
    use slop_symmetric::PseudoCompressionFunction;
    use sp1_primitives::{SP1Field, SP1GlobalContext};

    use super::compact_merkle_root;

    type GC = SP1GlobalContext;
    type Digest = <GC as IopCtx>::Digest;

    /// A distinct digest per index.
    fn leaf(x: u32) -> Digest {
        std::array::from_fn(|i| SP1Field::from_canonical_u32(x * 8 + i as u32 + 1))
    }

    #[test]
    fn compact_merkle_root_matches_hand_computed_shapes() {
        let (_, c) = GC::default_hasher_and_compressor();
        let l: [Digest; 5] = std::array::from_fn(|i| leaf(i as u32));

        // A single leaf is its own root.
        assert_eq!(compact_merkle_root::<GC>(&l[..1], &c), l[0]);

        // Two leaves: H(c0, c1).
        assert_eq!(compact_merkle_root::<GC>(&l[..2], &c), c.compress([l[0], l[1]]));

        // Three leaves: H(H(c0, c1), c2) — the lone trailing node is promoted, not hashed.
        let h01 = c.compress([l[0], l[1]]);
        assert_eq!(compact_merkle_root::<GC>(&l[..3], &c), c.compress([h01, l[2]]));

        // Five leaves: H(H(H(c0, c1), H(c2, c3)), c4).
        let h23 = c.compress([l[2], l[3]]);
        let h0123 = c.compress([h01, h23]);
        assert_eq!(compact_merkle_root::<GC>(&l[..5], &c), c.compress([h0123, l[4]]));
    }
}
