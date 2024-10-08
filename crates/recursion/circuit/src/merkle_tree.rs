use std::fmt::Debug;

use rayon::prelude::*;

use p3_field::Field;
use p3_util::{reverse_bits_len, reverse_slice_index_bits};
use serde::{Deserialize, Serialize};
use sp1_core_machine::utils::log2_strict_usize;
use sp1_recursion_compiler::ir::Builder;

use crate::{
    hash::{FieldHasher, FieldHasherVariable},
    stark::MerkleProofVariable,
    CircuitConfig,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "HV::Digest: Serialize"))]
#[serde(bound(deserialize = "HV::Digest: Deserialize<'de>"))]
pub struct MerkleTree<F: Field, HV: FieldHasher<F>> {
    /// The height of the tree, not counting the root layer. This is the same as the logarithm of the
    /// number of leaves.
    pub height: usize,

    /// All the layers but the root. If there are `n` leaves where `n` is a power of 2, there are
    /// `2n - 2` elements in this vector. The leaves are at the beginning of the vector.
    pub digest_layers: Vec<HV::Digest>,
}
pub struct VcsError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "HV::Digest: Serialize"))]
#[serde(bound(deserialize = "HV::Digest: Deserialize<'de>"))]
pub struct MerkleProof<F: Field, HV: FieldHasher<F>> {
    pub index: usize,
    pub path: Vec<HV::Digest>,
}

impl Debug for VcsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VcsError")
    }
}

impl<F: Field, HV: FieldHasher<F>> MerkleTree<F, HV> {
    pub fn commit(leaves: Vec<HV::Digest>) -> (HV::Digest, Self) {
        assert!(!leaves.is_empty());
        let new_len = leaves.len().next_power_of_two();
        let height = log2_strict_usize(new_len);

        // Pre-allocate the vector.
        let mut digest_layers = Vec::with_capacity(2 * new_len - 2);

        // If `leaves.len()` is not a power of 2, we pad the leaves with default values.
        let mut last_layer = leaves;
        let old_len = last_layer.len();
        for _ in old_len..new_len {
            last_layer.push(HV::Digest::default());
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
                    HV::constant_compress([left, right])
                })
                .collect_into_vec(&mut next_layer);
            digest_layers.extend(next_layer.iter());

            last_layer = next_layer;
        }

        debug_assert_eq!(digest_layers.len(), 2 * new_len - 2);

        let root = HV::constant_compress([last_layer[0], last_layer[1]]);
        (root, Self { height, digest_layers })
    }

    pub fn open(&self, index: usize) -> (HV::Digest, MerkleProof<F, HV>) {
        let mut path = Vec::with_capacity(self.height);
        let mut bit_rev_index = reverse_bits_len(index, self.height);
        let value = self.digest_layers[bit_rev_index];

        // Variable to keep track index of the first element in the current layer.
        let mut offset = 0;
        for i in 0..self.height {
            let sibling = if bit_rev_index % 2 == 0 {
                self.digest_layers[offset + bit_rev_index + 1]
            } else {
                self.digest_layers[offset + bit_rev_index - 1]
            };
            path.push(sibling);
            bit_rev_index >>= 1;

            // The current layer has 1 << (height - i) elements, so we shift offset by that amount.
            offset += 1 << (self.height - i);
        }
        debug_assert_eq!(path.len(), self.height);
        (value, MerkleProof { index, path })
    }

    pub fn verify(
        proof: MerkleProof<F, HV>,
        value: HV::Digest,
        commitment: HV::Digest,
    ) -> Result<(), VcsError> {
        let MerkleProof { index, path } = proof;

        let mut value = value;

        let mut index = reverse_bits_len(index, path.len());

        for sibling in path {
            // If the index is odd, swap the order of [value, sibling].
            let new_pair = if index % 2 == 0 { [value, sibling] } else { [sibling, value] };
            value = HV::constant_compress(new_pair);
            index >>= 1;
        }
        if value == commitment {
            Ok(())
        } else {
            Err(VcsError)
        }
    }
}

pub fn verify<C: CircuitConfig, HV: FieldHasherVariable<C>>(
    builder: &mut Builder<C>,
    proof: MerkleProofVariable<C, HV>,
    value: HV::DigestVariable,
    commitment: HV::DigestVariable,
) {
    let mut value = value;
    for (sibling, bit) in proof.path.iter().zip(proof.index.iter().rev()) {
        let sibling = *sibling;

        // If the index is odd, swap the order of [value, sibling].
        let new_pair = HV::select_chain_digest(builder, *bit, [value, sibling]);
        value = HV::compress(builder, new_pair);
    }
    HV::assert_digest_eq(builder, value, commitment);
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_util::log2_ceil_usize;
    use rand::rngs::OsRng;
    use sp1_recursion_compiler::{
        config::InnerConfig,
        ir::{Builder, Felt},
    };
    use sp1_recursion_core::DIGEST_SIZE;
    use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
    use zkhash::ark_ff::UniformRand;

    use crate::{
        merkle_tree::{verify, MerkleTree},
        stark::MerkleProofVariable,
        utils::tests::run_test_recursion,
        CircuitConfig,
    };
    type C = InnerConfig;
    type F = BabyBear;
    type HV = BabyBearPoseidon2;

    #[test]
    fn test_merkle_tree_inner() {
        let mut rng = OsRng;
        let mut builder = Builder::<InnerConfig>::default();
        // Run five times with different randomness.
        for _ in 0..5 {
            // Test with different number of leaves.
            for j in 2..20 {
                let leaves: Vec<[F; DIGEST_SIZE]> =
                    (0..j).map(|_| std::array::from_fn(|_| F::rand(&mut rng))).collect();
                let (root, tree) = MerkleTree::<BabyBear, HV>::commit(leaves.to_vec());
                for (i, leaf) in leaves.iter().enumerate() {
                    let (_, proof) = MerkleTree::<BabyBear, HV>::open(&tree, i);
                    MerkleTree::<BabyBear, HV>::verify(proof.clone(), *leaf, root).unwrap();
                    let (value_variable, path_variable): ([Felt<_>; 8], Vec<[Felt<_>; 8]>) = (
                        std::array::from_fn(|i| builder.constant(leaf[i])),
                        proof
                            .path
                            .iter()
                            .map(|x| std::array::from_fn(|i| builder.constant(x[i])))
                            .collect_vec(),
                    );

                    let index_var = builder.constant(BabyBear::from_canonical_usize(i));
                    let index_bits = C::num2bits(&mut builder, index_var, log2_ceil_usize(j));
                    let root_variable: [Felt<_>; 8] =
                        root.iter().map(|x| builder.constant(*x)).collect_vec().try_into().unwrap();

                    let proof_variable = MerkleProofVariable::<InnerConfig, BabyBearPoseidon2> {
                        index: index_bits,
                        path: path_variable,
                    };

                    verify::<InnerConfig, BabyBearPoseidon2>(
                        &mut builder,
                        proof_variable,
                        value_variable,
                        root_variable,
                    );
                }
            }
        }

        run_test_recursion(builder.into_operations(), std::iter::empty());
    }
}
