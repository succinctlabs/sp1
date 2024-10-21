pub(crate) const GAMMA: &str = "gamma";
pub(crate) const BETA: &str = "beta";
pub(crate) const ALPHA: &str = "alpha";
pub(crate) const ZETA: &str = "zeta";

mod converter;
mod hash_to_field;
mod kzg;
mod proof;
mod transcript;
mod verify;

pub(crate) mod error;

pub(crate) use converter::{load_plonk_proof_from_bytes, load_plonk_verifying_key_from_bytes};
pub(crate) use proof::PlonkProof;
pub(crate) use verify::verify_plonk;

use bn::Fr;
use error::PlonkError;
/// A verifier for Plonk zero-knowledge proofs.
#[derive(Debug)]
pub struct PlonkVerifier;

impl PlonkVerifier {
    /// Verifies a Plonk proof.
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
    /// or a `PlonkError` if verification fails.
    pub fn verify(proof: &[u8], vk: &[u8], public_inputs: &[Fr]) -> Result<bool, PlonkError> {
        let proof = load_plonk_proof_from_bytes(proof).unwrap();
        let vk = load_plonk_verifying_key_from_bytes(vk).unwrap();

        verify_plonk(&vk, &proof, public_inputs)
    }
}
