pub mod utils;

use serde::{Deserialize, Serialize};
use crate::utils::sha256_hash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CircuitInput {
    pub public_input_merkle_root: [u8; 32],
    pub public_value: u32,
    pub witness: Vec<u32>,
}

/// A toy example of cubic computation
pub fn cubic(n: u32) -> u32 {
    n.wrapping_mul(n).wrapping_mul(n)
}

/// Verify last prover's proof
pub fn verify_proof(vkey_hash: &[u32; 8], public_input_merkle_root: &[u8; 32]) {
    sp1_zkvm::lib::verify::verify_sp1_proof(vkey_hash, &sha256_hash(public_input_merkle_root));
}

/// Construct a merkle tree for all public inputs avoiding commit these public inputs directly
pub fn merkle_tree_public_input(
    public_input: Vec<u32>,
    public_value: u32,
) -> [u8; 32] {
    let public_input_hashes = public_input
        .iter()
        .chain([public_value].iter())
        .map(|pi| sha256_hash(&pi.to_le_bytes()))
        .collect::<Vec<_>>();
    utils::get_merkle_root(public_input_hashes)
}
