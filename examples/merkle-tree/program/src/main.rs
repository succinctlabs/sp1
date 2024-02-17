//! A simple program to be proven inside the zkVM.

#![no_main]

use alloy_merkle_tree::tree::MerkleTree;
use alloy_primitives::{Uint, B256};
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let count = sp1_zkvm::io::read::<u64>();

    let mut tree = MerkleTree::new();
    for i in 0..count {
        tree.insert(B256::from(Uint::from(i)));
    }
    tree.finish();

    for i in 0..count {
        let proof = tree.create_proof(&B256::from(Uint::from(i))).unwrap();
        assert!(MerkleTree::verify_proof(&proof));
    }

    sp1_zkvm::io::write(&count);
}
