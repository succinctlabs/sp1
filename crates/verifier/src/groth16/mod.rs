mod converter;
pub(crate) mod error;
mod verify;

pub(crate) use converter::{load_groth16_proof_from_bytes, load_groth16_verifying_key_from_bytes};
pub(crate) use verify::*;

use bn::Fr;
use error::Groth16Error;

/// A verifier for Groth16 zero-knowledge proofs.
#[derive(Debug)]
pub struct Groth16Verifier;

impl Groth16Verifier {
    /// Verifies a Groth16 proof.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof bytes.
    /// * `vk` - The verification key bytes.
    /// * `public_inputs` - The public inputs.
    ///
    /// # Returns
    ///
    /// A `Result` containing a boolean indicating whether the proof is valid,
    /// or a `Groth16Error` if verification fails.
    pub fn verify(proof: &[u8], vk: &[u8], public_inputs: &[Fr]) -> Result<bool, Groth16Error> {
        let proof = load_groth16_proof_from_bytes(proof).unwrap();
        let vk = load_groth16_verifying_key_from_bytes(vk).unwrap();

        verify_groth16(&vk, &proof, public_inputs)
    }
}
