use crate::{Groth16Verifier, PlonkVerifier};
use sp1_sdk::SP1ProofWithPublicValues;

extern crate std;

#[test]
fn test_verify_groth16() {
    // Location of the serialized SP1ProofWithPublicValues. This proof was generated with the
    // fibonacci example in `examples/fibonacci/program`.
    let proof_file = "test_binaries/fib_groth_300.bin";

    // Load the saved proof and extract the proof and public inputs.
    let sp1_proof_with_public_values = SP1ProofWithPublicValues::load(proof_file).unwrap();

    let proof = sp1_proof_with_public_values.bytes();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

    // This vkey hash was derived by calling `vk.bytes32()` on the verifying key.
    let vkey_hash = "0x0051835c0ba4b1ce3e6c5f4c5ab88a41e3eb1bc725d383f12255028ed76bd9a7";

    let is_valid =
        Groth16Verifier::verify(&proof, &public_inputs, vkey_hash, &crate::GROTH16_VK_BYTES)
            .expect("Groth16 proof is invalid");

    if !is_valid {
        panic!("Groth16 proof is invalid");
    }
}

#[test]
fn test_verify_plonk() {
    // Location of the serialized SP1ProofWithPublicValues. This proof was generated with the
    // fibonacci example in `examples/fibonacci/program`.
    let proof_file = "test_binaries/fib_plonk_300.bin";

    // Load the saved proof and extract the proof and public inputs.
    let sp1_proof_with_public_values = SP1ProofWithPublicValues::load(proof_file).unwrap();

    let proof = sp1_proof_with_public_values.raw_with_checksum();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

    // This vkey hash was derived by calling `vk.bytes32()` on the verifying key.
    let vkey_hash = "0x0051835c0ba4b1ce3e6c5f4c5ab88a41e3eb1bc725d383f12255028ed76bd9a7";

    let is_valid = PlonkVerifier::verify(&proof, &public_inputs, vkey_hash, &crate::PLONK_VK_BYTES)
        .expect("Plonk proof is invalid");

    if !is_valid {
        panic!("Plonk proof is invalid");
    }
}
