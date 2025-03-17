//! A simple program that aggregates the proofs of multiple programs proven with the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

pub fn words_to_bytes_le(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let word_bytes = words[i].to_le_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    bytes
}

/// Encode a vkey and a committed value into a single byte array.
///
/// ( words_to_bytes_le(vkey) || (committed_value.len() as u32).to_be_bytes() || committed_value )
pub fn commit_proof_pair(vkey: &[u32; 8], committed_value: &Vec<u8>) -> Vec<u8> {
    let mut res = Vec::new();
    res.extend_from_slice(&words_to_bytes_le(vkey));
    // Note we use big endian because abi.encodePacked in solidity does also
    res.extend_from_slice(&(committed_value.len() as u32).to_be_bytes());
    res.extend_from_slice(committed_value);
    res
}

/// Computes hash of a leaf in a merkle tree.
///
/// A leaf in a merkle tree is a pair of a verification key and a committed value.
/// The leaf is encoded as a byte array using `commit_proof_pair` and then hashed using sha256.
pub fn compute_leaf_hash(vkey: &[u32; 8], committed_value: &Vec<u8>) -> [u8; 32] {
    // encode the leaf as a byte array
    let leaf = commit_proof_pair(vkey, committed_value);
    let digest = Sha256::digest(&leaf);
    let mut res = [0u8; 32];
    res.copy_from_slice(&digest);
    res
}

/// Hashes a pair of already hashed leaves.
///
/// The hash is computed as sha256(left || right).
pub fn hash_pair(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut res = [0u8; 32];
    res.copy_from_slice(&digest);
    res
}

/// Computes the root of a merkle tree given the leaves.
///
/// The leaves are hashed using `compute_leaf_hash` and then the hashes are combined to form the root.
/// The root is computed by hashing pairs of hashes until only one hash remains.
pub fn compute_merkle_root(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }


    while leaves.len() > 1 {
        let mut next = Vec::new();
        for i in (0..leaves.len()).step_by(2) {
            let left = &leaves[i];
            let right = if i + 1 < leaves.len() { &leaves[i + 1] } else { &leaves[i] };
            next.push(hash_pair(left, right));
        }
        leaves = next;
    }
    leaves[0]
}

pub fn main() {
    // Read the verification keys.
    let vkeys = sp1_zkvm::io::read::<Vec<[u32; 8]>>();

    // Read the public values.
    let public_values = sp1_zkvm::io::read::<Vec<Vec<u8>>>();

    // Verify the proofs.
    assert_eq!(vkeys.len(), public_values.len());
    for i in 0..vkeys.len() {
        let vkey = &vkeys[i];
        let public_values = &public_values[i];
        let public_values_digest = Sha256::digest(public_values);
        sp1_zkvm::lib::verify::verify_sp1_proof(vkey, &public_values_digest.into());
    }

    // Convert the (vkey, public_value) pairs into leaves of a merkle tree.
    let leaves: Vec<[u8; 32]> = vkeys
        .iter()
        .zip(public_values.iter())
        .map(|(vkey, public_value)| compute_leaf_hash(vkey, public_value))
        .collect();

    // Traverse the merkle tree bottom-up to compute the root.
    let merkle_root = compute_merkle_root(leaves);

    // Commit the root.
    sp1_zkvm::io::commit_slice(&merkle_root);
}
