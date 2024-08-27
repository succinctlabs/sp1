use core::marker::PhantomData;
use std::fmt::Debug;

use itertools::Itertools;
use p3_field::Field;
use sp1_core_machine::utils::log2_strict_usize;
use sp1_recursion_compiler::ir::{Builder, Config};

use crate::{
    hash::{FieldHasher, FieldHasherVariable},
    CircuitConfig,
};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct MerkleTree<F: Field, HV: FieldHasher<F>> {
    pub height: usize,
    /// The root is at index 0, its children at index 1 and 2, etc.
    pub digest_layers: Vec<HV::Digest>,
}
pub struct VcsError;

impl Debug for VcsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VcsError")
    }
}

impl<F: Field, HV: FieldHasher<F>> MerkleTree<F, HV> {
    pub fn commit(leaves: Vec<HV::Digest>) -> (HV::Digest, Self) {
        assert!(leaves.len() > 0);
        let new_len = leaves.len().next_power_of_two();
        let height = log2_strict_usize(new_len);

        let mut digest_layers = vec![HV::Digest::default(); 2 * new_len - 1];

        for i in 0..leaves.len() {
            digest_layers[i + new_len - 1] = leaves[i];
        }

        let mut last_layer = leaves.clone();

        for i in 0..height - 1 {
            println!("Layer: {}", i);
            let mut next_layer = Vec::with_capacity(last_layer.len() / 2);
            for (a, b) in last_layer.iter().tuples() {
                next_layer.push(HV::constant_compress([*a, *b]));
            }
            // Load the new layer at the beginning of the vector.
            for j in 0..next_layer.len() {
                digest_layers[(new_len >> (i + 1)) - 1 + j] = next_layer[j];
            }

            last_layer = next_layer;
        }
        let root = *digest_layers.last().unwrap();
        println!("Leaves: {:?}", leaves);
        println!("Root: {:?}", root);
        println!("Digest layers: {:?}", digest_layers);
        (root, Self { height, digest_layers })
    }

    pub fn open(&self, index: usize) -> (HV::Digest, Vec<HV::Digest>) {
        let mut path = Vec::with_capacity(self.height);
        let value = self.digest_layers[index + (1 << self.height) - 1];
        println!("trying to open index: {}", index);
        let mut index = index + (1 << self.height) - 1;
        println!("Starting index: {}", index);
        for _ in 0..self.height {
            let sibling = if index % 2 == 1 {
                println!("Sibling at index: {}", index + 1);
                self.digest_layers[index + 1]
            } else {
                println!("Sibling at index: {}", index - 1);
                self.digest_layers[index - 1]
            };
            path.push(sibling);
            index = (index + 1) / 2 - 1;
            println!("New index: {}", index);
        }
        (value, path)
    }

    pub fn verify(
        mut index: usize,
        value: HV::Digest,
        path: &[HV::Digest],
        commitment: HV::Digest,
    ) -> Result<(), VcsError> {
        println!("Number of siblings: {}", path.len());
        let mut value = value;
        index += (1 << path.len()) - 1;
        for sibling in path {
            println!("Verifying Index: {}", index);
            let sibling = *sibling;
            let new_pair = if index % 2 == 0 {
                println!("Swapping order.");
                [sibling, value]
            } else {
                [value, sibling]
            };
            value = HV::constant_compress(new_pair);
            index = (index + 1) / 2 - 1;
            println!("New index: {}", index);
        }
        if value == commitment {
            Ok(())
        } else {
            Err(VcsError)
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_bn254_fr::Bn254Fr;
    use p3_field::{AbstractField, Field};
    use sp1_recursion_core_v2::stark::config::BabyBearPoseidon2Outer;

    use crate::{hash::FieldHasher, merkle_tree::MerkleTree};

    fn setup_test_merkle_tree<F: Field, HV: FieldHasher<F>>(leaves: &[HV::Digest]) {
        let (root, tree) = MerkleTree::<F, HV>::commit(leaves.to_vec());
        let (value0, path0) = tree.open(0);
        let (value1, path1) = tree.open(1);
        let (value2, path2) = tree.open(2);
        assert_eq!(value0, leaves[0]);
        assert_eq!(value1, leaves[1]);
        assert_eq!(value2, leaves[2]);
        MerkleTree::<F, HV>::verify(0, value0, &path0, root).unwrap();
        MerkleTree::<F, HV>::verify(1, value1, &path1, root).unwrap();
        MerkleTree::<F, HV>::verify(2, value2, &path2, root).unwrap();
    }

    #[test]
    fn test_merkle_tree() {
        setup_test_merkle_tree::<BabyBear, BabyBearPoseidon2Outer>(&[
            [Bn254Fr::one()],
            [Bn254Fr::two()],
            [Bn254Fr::from_canonical_u32(3)],
        ]);
    }
}
