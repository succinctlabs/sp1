use sp1_sdk::{install::try_install_circuit_artifacts, SP1ProofWithPublicValues};

extern crate std;

#[test]
fn test_verify_groth16() {
    // Location of the serialized SP1ProofWithPublicValues. See README.md for more information.
    let proof_file = "test_binaries/fibonacci-groth16.bin";

    // Load the saved proof and extract the proof and public inputs.
    let sp1_proof_with_public_values = SP1ProofWithPublicValues::load(proof_file).unwrap();

    let proof = sp1_proof_with_public_values.bytes();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

    // This vkey hash was derived by calling `vk.bytes32()` on the verifying key.
    let vkey_hash = "0x00e60860c07bfc6e4c480286c0ddbb879674eb47f84b4ef041cf858b17aa0ed1";

    let is_valid =
        crate::Groth16Verifier::verify(&proof, &public_inputs, vkey_hash, &crate::GROTH16_VK_BYTES)
            .expect("Groth16 proof is invalid");

    if !is_valid {
        panic!("Groth16 proof is invalid");
    }
}

#[test]
fn test_verify_plonk() {
    // Location of the serialized SP1ProofWithPublicValues. See README.md for more information.
    let proof_file = "test_binaries/fibonacci-plonk.bin";

    // Load the saved proof and extract the proof and public inputs.
    let sp1_proof_with_public_values = SP1ProofWithPublicValues::load(proof_file).unwrap();

    let proof = sp1_proof_with_public_values.raw_with_checksum();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

    // This vkey hash was derived by calling `vk.bytes32()` on the verifying key.
    let vkey_hash = "0x00e60860c07bfc6e4c480286c0ddbb879674eb47f84b4ef041cf858b17aa0ed1";

    let is_valid =
        crate::PlonkVerifier::verify(&proof, &public_inputs, vkey_hash, &crate::PLONK_VK_BYTES)
            .expect("Plonk proof is invalid");

    if !is_valid {
        panic!("Plonk proof is invalid");
    }
}

#[test]
fn test_vkeys() {
    let groth16_path = try_install_circuit_artifacts("groth16");
    let s3_vkey_path = groth16_path.join("groth16_vk.bin");
    let s3_vkey_bytes = std::fs::read(s3_vkey_path).unwrap();
    assert_eq!(s3_vkey_bytes, *crate::GROTH16_VK_BYTES);

    let plonk_path = try_install_circuit_artifacts("plonk");
    let s3_vkey_path = plonk_path.join("plonk_vk.bin");
    let s3_vkey_bytes = std::fs::read(s3_vkey_path).unwrap();
    assert_eq!(s3_vkey_bytes, *crate::PLONK_VK_BYTES);
}
