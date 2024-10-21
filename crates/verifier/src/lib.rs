#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

//! This crate provides verifiers for Groth16 and Plonk zero-knowledge proofs.
#![no_std]
extern crate alloc;

mod constants;
mod converter;
mod error;
mod groth16;

pub use groth16::Groth16Verifier;
#[cfg(feature = "getrandom")]
mod plonk;
#[cfg(feature = "getrandom")]
pub use plonk::PlonkVerifier;

#[cfg(test)]
mod tests {
    use crate::{Groth16Verifier, PlonkVerifier};
    use bn::Fr;
    use num_bigint::BigUint;
    use num_traits::Num;
    use sp1_sdk::SP1ProofWithPublicValues;

    const PLONK_VK_BYTES: &[u8] = include_bytes!("../../../../.sp1/circuits/v2.0.0/plonk_vk.bin");
    const GROTH16_VK_BYTES: &[u8] =
        include_bytes!("../../../../.sp1/circuits/v2.0.0/groth16_vk.bin");

    #[test]
    fn test_verify_groth16() {
        // Location of the serialized SP1ProofWithPublicValues
        let proof_file = "test_binaries/fibonacci_groth16_proof.bin";

        // Load the saved proof and convert it to the specified proof mode
        let (raw_proof, public_inputs) = SP1ProofWithPublicValues::load(proof_file)
            .map(|sp1_proof_with_public_values| {
                let proof = sp1_proof_with_public_values.proof.try_as_groth_16().unwrap();
                (hex::decode(proof.raw_proof).unwrap(), proof.public_inputs)
            })
            .expect("Failed to load proof");

        // Convert public inputs to byte representations
        let vkey_hash = BigUint::from_str_radix(&public_inputs[0], 10).unwrap().to_bytes_be();
        let committed_values_digest =
            BigUint::from_str_radix(&public_inputs[1], 10).unwrap().to_bytes_be();

        let vkey_hash = Fr::from_slice(&vkey_hash).expect("Unable to read vkey_hash");
        let committed_values_digest = Fr::from_slice(&committed_values_digest)
            .expect("Unable to read committed_values_digest");

        let is_valid = Groth16Verifier::verify(
            &raw_proof,
            GROTH16_VK_BYTES,
            &[vkey_hash, committed_values_digest],
        )
        .expect("Groth16 proof is invalid");

        if !is_valid {
            panic!("Groth16 proof is invalid");
        }
    }

    #[test]
    fn test_verify_plonk() {
        // Location of the serialized SP1ProofWithPublicValues
        let proof_file = "test_binaries/fibonacci_plonk_proof.bin";

        // Load the saved proof and convert it to the specified proof mode
        let (raw_proof, public_inputs) = SP1ProofWithPublicValues::load(proof_file)
            .map(|sp1_proof_with_public_values| {
                let proof = sp1_proof_with_public_values.proof.try_as_plonk().unwrap();
                (hex::decode(proof.raw_proof).unwrap(), proof.public_inputs)
            })
            .expect("Failed to load proof");

        // Convert public inputs to byte representations
        let vkey_hash = BigUint::from_str_radix(&public_inputs[0], 10).unwrap().to_bytes_be();
        let committed_values_digest =
            BigUint::from_str_radix(&public_inputs[1], 10).unwrap().to_bytes_be();

        let vkey_hash = Fr::from_slice(&vkey_hash).expect("Unable to read vkey_hash");
        let committed_values_digest = Fr::from_slice(&committed_values_digest)
            .expect("Unable to read committed_values_digest");

        let is_valid = PlonkVerifier::verify(
            &raw_proof,
            PLONK_VK_BYTES,
            &[vkey_hash, committed_values_digest],
        )
        .expect("Plonk proof is invalid");

        if !is_valid {
            panic!("Plonk proof is invalid");
        }
    }
}
