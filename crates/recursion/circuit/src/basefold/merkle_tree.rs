use crate::{hash::FieldHasher, CircuitConfig, FieldHasherVariable};
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use serde::{Deserialize, Serialize};
use slop_challenger::IopCtx;
use sp1_core_machine::utils::{log2_strict_usize, reverse_slice_index_bits};
use sp1_hypercube::MerkleProof;
use sp1_primitives::utils::reverse_bits_len;
use sp1_recursion_compiler::ir::Builder;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree<GC: IopCtx> {
    /// The height of the tree, not counting the root layer. This is the same as the logarithm of
    /// the number of leaves.
    pub height: usize,

    /// All the layers but the root. If there are `n` leaves where `n` is a power of 2, there are
    /// `2n - 2` elements in this vector. The leaves are at the beginning of the vector.
    pub digest_layers: Vec<GC::Digest>,
}

impl<GC: FieldHasher<Digest: Default>> MerkleTree<GC> {
    pub fn commit(leaves: Vec<GC::Digest>) -> (GC::Digest, Self) {
        assert!(!leaves.is_empty());
        let new_len = leaves.len().next_power_of_two();
        let height = log2_strict_usize(new_len);

        // Pre-allocate the vector.
        let mut digest_layers = Vec::with_capacity(2 * new_len - 2);

        // If `leaves.len()` is not a power of 2, we pad the leaves with default values.
        let mut last_layer = leaves;
        let old_len = last_layer.len();
        for _ in old_len..new_len {
            last_layer.push(GC::Digest::default());
        }

        // Store the leaves in bit-reversed order.
        reverse_slice_index_bits(&mut last_layer);

        digest_layers.extend(last_layer.iter());

        // Compute the rest of the layers.
        for _ in 0..height - 1 {
            let mut next_layer = Vec::with_capacity(last_layer.len() / 2);
            last_layer
                .par_chunks_exact(2)
                .map(|chunk| {
                    let [left, right] = chunk.try_into().unwrap();
                    GC::constant_compress([left, right])
                })
                .collect_into_vec(&mut next_layer);
            digest_layers.extend(next_layer.iter());

            last_layer = next_layer;
        }

        debug_assert_eq!(digest_layers.len(), 2 * new_len - 2);

        let root = GC::constant_compress([last_layer[0], last_layer[1]]);

        (root, Self { height, digest_layers })
    }

    pub fn open(&self, index: usize) -> (GC::Digest, MerkleProof<GC>) {
        let mut path = Vec::with_capacity(self.height);
        let mut bit_rev_index = reverse_bits_len(index, self.height);
        let value = self.digest_layers[bit_rev_index];

        // Variable to keep track index of the first element in the current layer.
        let mut offset = 0;
        for i in 0..self.height {
            let sibling = if bit_rev_index.is_multiple_of(2) {
                self.digest_layers[offset + bit_rev_index + 1]
            } else {
                self.digest_layers[offset + bit_rev_index - 1]
            };
            path.push(sibling);
            bit_rev_index >>= 1;

            // The current layer has 1 << (height - i) elements, so we shift offset by that amount.
            offset += 1 << (self.height - i);
        }
        assert_eq!(path.len(), self.height);
        (value, MerkleProof { index, path })
    }
}

pub fn verify<C: CircuitConfig, HV: FieldHasherVariable<C>>(
    builder: &mut Builder<C>,
    path: Vec<HV::DigestVariable>,
    index: Vec<C::Bit>,
    value: HV::DigestVariable,
    merkle_root: HV::DigestVariable,
) {
    let mut value = value;
    for (sibling, bit) in path.iter().zip(index.iter()) {
        let sibling = *sibling;
        // If the index is odd, swap the order of [value, sibling].
        let new_pair = HV::select_chain_digest(builder, *bit, [value, sibling]);
        value = HV::compress(builder, new_pair);
    }

    HV::assert_digest_eq(builder, value, merkle_root);
}

/// Verifies 8 Merkle paths of equal length against the same root, walking the paths in
/// lockstep so the compressions at each level form an independent 8-lane batch. Lane-wise
/// identical to [`verify`].
pub fn verify_batch8<C: CircuitConfig, HV: FieldHasherVariable<C>>(
    builder: &mut Builder<C>,
    paths: [Vec<HV::DigestVariable>; 8],
    indices: [Vec<C::Bit>; 8],
    values: [HV::DigestVariable; 8],
    merkle_root: HV::DigestVariable,
) {
    // The scalar `verify` zips the path with the index bits, so each lane walks
    // `min(path.len(), index.len())` levels; lockstep requires that count to be uniform.
    let num_levels = paths[0].len().min(indices[0].len());
    assert!(
        paths
            .iter()
            .zip(indices.iter())
            .all(|(path, index)| path.len().min(index.len()) == num_levels),
        "batched Merkle verification requires equal path lengths"
    );

    let mut values = values;
    for level in 0..num_levels {
        let pairs: [[HV::DigestVariable; 2]; 8] = core::array::from_fn(|lane| {
            // If the index is odd, swap the order of [value, sibling].
            HV::select_chain_digest(
                builder,
                indices[lane][level],
                [values[lane], paths[lane][level]],
            )
        });
        values = HV::compress_batch8(builder, pairs);
    }

    for value in values {
        HV::assert_digest_eq(builder, value, merkle_root);
    }
}
