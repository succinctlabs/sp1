pub mod utils;

use serde::{Deserialize, Serialize};
use crate::utils::sha256_hash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CircuitInput {
    pub public_input_hash: [u8; 32],
    pub public_value: u32,
    pub private_value: u32,
}

impl CircuitInput {
    pub fn new(public_input_hash: [u8; 32], public_value: u32, private_value: u32) -> Self {
        Self {
            public_input_hash,
            public_value,
            private_value,
        }
    }
}

/// Given `x_0, x_1, x_2, ...., x_{n - 1}` as public values, we want to know `x_0^3 + x_1^3 +
/// x_2^3 + ...+ x_{n - 1}^3`
/// 
/// core function, say `f(y, x) = y + x^3`, where:
/// 1) y, is the accumulation result, marked as private value
/// 2) x, is the public value
pub fn acc_cubic(public_value: u32, private_value: u32) -> u32 {
    private_value.wrapping_add(public_value.wrapping_mul(public_value).wrapping_mul(public_value))
}

/// Verify last prover's proof with two public values:
/// 1) public_input_hash, which is a recursive hash of all public values of acc_cubic `f(y, x)`
/// 2) y, last prover's accumulated result 
pub fn verify_proof(vkey_hash: &[u32; 8], public_input_hash: &[u8; 32], private_value: u32) {
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(public_input_hash);
    bytes.extend_from_slice(&private_value.to_le_bytes());
    sp1_zkvm::lib::verify::verify_sp1_proof(vkey_hash, &sha256_hash(&bytes));
}
