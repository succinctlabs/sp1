pub mod utils;

use serde::{Deserialize, Serialize};
use crate::utils::sha256_hash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CircuitInput {
    pub public_input_merkle_root: [u8; 32],
    pub public_value: u32,
    pub private_value: u32,
    pub witness: Vec<u32>,
}

impl CircuitInput {
    pub fn new(public_input_merkle_root: [u8; 32], public_value: u32, private_value: u32, witness: Vec<u32>) -> Self {
        Self {
            public_input_merkle_root,
            public_value,
            private_value,
            witness,
        }
    }
}

/// A toy example of accumulation of cubic 
pub fn acc_cubic(public_value: u32, private_value: u32) -> u32 {
    private_value.wrapping_add(public_value.wrapping_mul(public_value).wrapping_mul(public_value))
}

/// Verify last prover's proof
pub fn verify_proof(vkey_hash: &[u32; 8], public_input_merkle_root: &[u8; 32], private_value: u32) {
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(public_input_merkle_root);
    bytes.extend_from_slice(&private_value.to_le_bytes());
    sp1_zkvm::lib::verify::verify_sp1_proof(vkey_hash, &sha256_hash(&bytes));
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
