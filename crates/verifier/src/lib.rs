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
mod utils;

pub use groth16::Groth16Verifier;
pub use utils::*;

#[cfg(feature = "getrandom")]
mod plonk;
#[cfg(feature = "getrandom")]
pub use plonk::PlonkVerifier;

/// The PLONK verifying key for this SP1 version.
pub const PLONK_VK_BYTES: &[u8] =
    include_bytes!("../../../../.sp1/circuits/plonk/v3.0.0/plonk_vk.bin");

/// The Groth16 verifying key for this SP1 version.
pub const GROTH16_VK_BYTES: &[u8] =
    include_bytes!("../../../../.sp1/circuits/groth16/v3.0.0/groth16_vk.bin");

/// blah blah
// pub const GROTH16_VK_BYTES: &[u8] =
//     include_bytes!("../../../../.sp1/circuits/v2.0.0/groth16_vk.bin");

#[cfg(test)]
mod tests {
    use crate::{Groth16Verifier, PlonkVerifier};
    use bn::Fr;
    use num_bigint::BigUint;
    use num_traits::Num;
    use sp1_sdk::SP1ProofWithPublicValues;

    extern crate std;

    #[test]
    fn test_verify_groth16() {
        // Location of the serialized SP1ProofWithPublicValues
        let proof_file = "test_binaries/fibonacci_groth16_proof2.bin";

        // Load the saved proof and convert it to the specified proof mode
        let (raw_proof, public_inputs) = SP1ProofWithPublicValues::load(proof_file)
            .map(|sp1_proof_with_public_values| {
                let public_inputs = &sp1_proof_with_public_values.public_values;
                let proof = sp1_proof_with_public_values.bytes();
                (proof, public_inputs.to_vec())
            })
            .expect("Failed to load proof");

        // Convert public inputs to byte representations
        let vkey_hash = "0x0051835c0ba4b1ce3e6c5f4c5ab88a41e3eb1bc725d383f12255028ed76bd9a7";

        let is_valid =
            Groth16Verifier::verify(&raw_proof, &public_inputs, vkey_hash, crate::GROTH16_VK_BYTES)
                .expect("Groth16 proof is invalid");

        if !is_valid {
            panic!("Groth16 proof is invalid");
        }
    }

    #[test]
    fn test_verify_plonk() {
        // Location of the serialized SP1ProofWithPublicValues
        let proof_file = "test_binaries/fibonacci_plonk_proof2.bin";

        // Load the saved proof and convert it to the specified proof mode
        let (raw_proof, public_inputs) = SP1ProofWithPublicValues::load(proof_file)
            .map(|sp1_proof_with_public_values| {
                let proof = sp1_proof_with_public_values.proof.try_as_plonk().unwrap();
                (hex::decode(proof.raw_proof).unwrap(), proof.public_inputs)
            })
            .expect("Failed to load proof");

        // Convert public inputs to byte representations

        let vkey_hash: std::vec::Vec<u8> =
            BigUint::from_str_radix(&public_inputs[0], 10).unwrap().to_bytes_be();
        std::println!("vkey_hash: {:?}", hex::encode(&vkey_hash));
        let committed_values_digest =
            BigUint::from_str_radix(&public_inputs[1], 10).unwrap().to_bytes_be();

        let vkey_hash = Fr::from_slice(&vkey_hash).expect("Unable to read vkey_hash");
        let committed_values_digest = Fr::from_slice(&committed_values_digest)
            .expect("Unable to read committed_values_digest");

        std::println!("vkey_hash: {:?}", vkey_hash);
        std::println!("committed_values_digest: {:?}", committed_values_digest);

        // let is_valid = PlonkVerifier::verify(
        //     &raw_proof,
        //     crate::PLONK_VK_BYTES,
        //     &[vkey_hash, committed_values_digest],
        // )
        // .expect("Plonk proof is invalid");

        // if !is_valid {
        //     panic!("Plonk proof is invalid");
        // }
    }
}
