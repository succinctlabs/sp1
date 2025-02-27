use serial_test::serial;
use sp1_sdk::{install::try_install_circuit_artifacts, HashableKey, ProverClient, SP1Stdin};
use test_artifacts::FIBONACCI_ELF;
use crate::{error::Error, Groth16Error, PlonkError};

/// Offset value in the proof data; number of bytes to skip from the beginning of the proof.
const PROOF_OFFSET: usize = 4;

#[cfg(feature = "ark")]
fn verify_with_ark(proof: &[u8], public_inputs: &[u8], vkey_hash: &[u8]) {
    use ark_bn254::Bn254;
    use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16};
    use crate::{
        decode_sp1_vkey_hash, hash_public_inputs, load_ark_groth16_verifying_key_from_bytes,
        load_ark_proof_from_bytes, load_ark_public_inputs_from_bytes,
    };

    // Load the Ark proof starting from PROOF_OFFSET.
    let ark_proof = load_ark_proof_from_bytes(&proof[PROOF_OFFSET..])
        .expect("Failed to load Ark proof");
    let ark_vkey = load_ark_groth16_verifying_key_from_bytes(&crate::GROTH16_VK_BYTES)
        .expect("Failed to load Ark verifying key");
    let ark_public_inputs = load_ark_public_inputs_from_bytes(
        &decode_sp1_vkey_hash(vkey_hash).expect("Failed to decode vkey hash"),
        &hash_public_inputs(public_inputs),
    );
    Groth16::<Bn254, LibsnarkReduction>::verify_proof(&ark_vkey.into(), &ark_proof, &ark_public_inputs)
        .expect("Ark verification failed");
}

/// Sets up the client, proof, public inputs, and vkey hash for Groth16.
fn setup_proof_groth16() -> (ProverClient, Vec<u8>, Vec<u8>, [u8; 32]) {
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(FIBONACCI_ELF);
    let sp1_proof = client
        .prove(&pk, &SP1Stdin::new())
        .groth16()
        .run()
        .expect("Failed to generate Groth16 proof");
    let proof = sp1_proof.bytes();
    let public_inputs = sp1_proof.public_values.to_vec();
    let vkey_hash = vk.bytes32();
    (client, proof, public_inputs, vkey_hash)
}

/// Sets up the client, proof, public inputs, and vkey hash for Plonk.
fn setup_proof_plonk() -> (ProverClient, Vec<u8>, Vec<u8>, [u8; 32]) {
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(FIBONACCI_ELF);
    let sp1_proof = client
        .prove(&pk, &SP1Stdin::new())
        .plonk()
        .run()
        .expect("Failed to generate Plonk proof");
    let proof = sp1_proof.bytes();
    let public_inputs = sp1_proof.public_values.to_vec();
    let vkey_hash = vk.bytes32();
    (client, proof, public_inputs, vkey_hash)
}

#[serial]
#[test]
fn test_verify_groth16() {
    const GROTH16_ELF: &[u8] = include_bytes!("../guest-verify-programs/groth16_verify");

    // Setup and generate Groth16 proof.
    let (client, proof, public_inputs, vkey_hash) = setup_proof_groth16();

    // Ark-based verification (if the feature is enabled).
    cfg_if::cfg_if! {
        if #[cfg(feature = "ark")] {
            verify_with_ark(&proof, &public_inputs, &vkey_hash);
        }
    }

    // Local Groth16 verification.
    crate::Groth16Verifier::verify(&proof, &public_inputs, &vkey_hash, &crate::GROTH16_VK_BYTES)
        .expect("Groth16 proof verification failed");

    // VM verification: send proof, public inputs, and vkey hash to the VM.
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&proof);
    stdin.write_slice(&public_inputs);
    stdin.write(&vkey_hash);

    client.execute(GROTH16_ELF, &stdin)
        .run()
        .expect("VM Groth16 verification failed");
}

#[serial]
#[test]
fn test_verify_invalid_groth16() {
    // Setup and generate Groth16 proof.
    let (_client, proof, public_inputs, vkey_hash) = setup_proof_groth16();

    // Attempt verification with an invalid proof (intentionally incomplete: only the first byte).
    let result = crate::Groth16Verifier::verify(
        &proof[..1],
        &public_inputs,
        &vkey_hash,
        &crate::GROTH16_VK_BYTES,
    );

    assert!(
        matches!(result, Err(Groth16Error::GeneralError(Error::InvalidData))),
        "Unexpected error: invalid Groth16 proof verification"
    );
}

#[serial]
#[test]
fn test_verify_plonk() {
    const PLONK_ELF: &[u8] = include_bytes!("../guest-verify-programs/plonk_verify");

    // Setup and generate Plonk proof.
    let (client, proof, public_inputs, vkey_hash) = setup_proof_plonk();

    // Local Plonk verification.
    crate::PlonkVerifier::verify(&proof, &public_inputs, &vkey_hash, &crate::PLONK_VK_BYTES)
        .expect("Plonk proof verification failed");

    // VM verification: send proof, public inputs, and vkey hash to the VM.
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&proof);
    stdin.write_slice(&public_inputs);
    stdin.write(&vkey_hash);

    client.execute(PLONK_ELF, &stdin)
        .run()
        .expect("VM Plonk verification failed");
}

#[serial]
#[test]
fn test_verify_invalid_plonk() {
    // Setup and generate Plonk proof.
    let (_client, proof, public_inputs, vkey_hash) = setup_proof_plonk();

    // Attempt verification with an invalid proof (intentionally incomplete: only the first byte).
    let result = crate::PlonkVerifier::verify(
        &proof[..1],
        &public_inputs,
        &vkey_hash,
        &crate::PLONK_VK_BYTES,
    );

    assert!(
        matches!(result, Err(PlonkError::GeneralError(Error::InvalidData))),
        "Unexpected error: invalid Plonk proof verification"
    );
}

#[serial]
#[test]
fn test_vkeys() {
    let groth16_path = try_install_circuit_artifacts("groth16");
    let s3_vkey_path = groth16_path.join("groth16_vk.bin");
    let s3_vkey_bytes = std::fs::read(s3_vkey_path).expect("Failed to read Groth16 vkey");
    assert_eq!(
        s3_vkey_bytes,
        *crate::GROTH16_VK_BYTES,
        "Groth16 vkey mismatch"
    );

    let plonk_path = try_install_circuit_artifacts("plonk");
    let s3_vkey_path = plonk_path.join("plonk_vk.bin");
    let s3_vkey_bytes = std::fs::read(s3_vkey_path).expect("Failed to read Plonk vkey");
    assert_eq!(
        s3_vkey_bytes,
        *crate::PLONK_VK_BYTES,
        "Plonk vkey mismatch"
    );
}use serial_test::serial;
use sp1_sdk::{install::try_install_circuit_artifacts, HashableKey, ProverClient, SP1Stdin};
use test_artifacts::FIBONACCI_ELF;
use crate::{error::Error, Groth16Error, PlonkError};

/// Offset value in the proof data; number of bytes to skip from the beginning of the proof.
const PROOF_OFFSET: usize = 4;

#[cfg(feature = "ark")]
fn verify_with_ark(proof: &[u8], public_inputs: &[u8], vkey_hash: &[u8]) {
    use ark_bn254::Bn254;
    use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16};
    use crate::{
        decode_sp1_vkey_hash, hash_public_inputs, load_ark_groth16_verifying_key_from_bytes,
        load_ark_proof_from_bytes, load_ark_public_inputs_from_bytes,
    };

    // Load the Ark proof starting from PROOF_OFFSET.
    let ark_proof = load_ark_proof_from_bytes(&proof[PROOF_OFFSET..])
        .expect("Failed to load Ark proof");
    let ark_vkey = load_ark_groth16_verifying_key_from_bytes(&crate::GROTH16_VK_BYTES)
        .expect("Failed to load Ark verifying key");
    let ark_public_inputs = load_ark_public_inputs_from_bytes(
        &decode_sp1_vkey_hash(vkey_hash).expect("Failed to decode vkey hash"),
        &hash_public_inputs(public_inputs),
    );
    Groth16::<Bn254, LibsnarkReduction>::verify_proof(&ark_vkey.into(), &ark_proof, &ark_public_inputs)
        .expect("Ark verification failed");
}

/// Sets up the client, proof, public inputs, and vkey hash for Groth16.
fn setup_proof_groth16() -> (ProverClient, Vec<u8>, Vec<u8>, [u8; 32]) {
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(FIBONACCI_ELF);
    let sp1_proof = client
        .prove(&pk, &SP1Stdin::new())
        .groth16()
        .run()
        .expect("Failed to generate Groth16 proof");
    let proof = sp1_proof.bytes();
    let public_inputs = sp1_proof.public_values.to_vec();
    let vkey_hash = vk.bytes32();
    (client, proof, public_inputs, vkey_hash)
}

/// Sets up the client, proof, public inputs, and vkey hash for Plonk.
fn setup_proof_plonk() -> (ProverClient, Vec<u8>, Vec<u8>, [u8; 32]) {
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(FIBONACCI_ELF);
    let sp1_proof = client
        .prove(&pk, &SP1Stdin::new())
        .plonk()
        .run()
        .expect("Failed to generate Plonk proof");
    let proof = sp1_proof.bytes();
    let public_inputs = sp1_proof.public_values.to_vec();
    let vkey_hash = vk.bytes32();
    (client, proof, public_inputs, vkey_hash)
}

#[serial]
#[test]
fn test_verify_groth16() {
    const GROTH16_ELF: &[u8] = include_bytes!("../guest-verify-programs/groth16_verify");

    // Setup and generate Groth16 proof.
    let (client, proof, public_inputs, vkey_hash) = setup_proof_groth16();

    // Ark-based verification (if the feature is enabled).
    cfg_if::cfg_if! {
        if #[cfg(feature = "ark")] {
            verify_with_ark(&proof, &public_inputs, &vkey_hash);
        }
    }

    // Local Groth16 verification.
    crate::Groth16Verifier::verify(&proof, &public_inputs, &vkey_hash, &crate::GROTH16_VK_BYTES)
        .expect("Groth16 proof verification failed");

    // VM verification: send proof, public inputs, and vkey hash to the VM.
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&proof);
    stdin.write_slice(&public_inputs);
    stdin.write(&vkey_hash);

    client.execute(GROTH16_ELF, &stdin)
        .run()
        .expect("VM Groth16 verification failed");
}

#[serial]
#[test]
fn test_verify_invalid_groth16() {
    // Setup and generate Groth16 proof.
    let (_client, proof, public_inputs, vkey_hash) = setup_proof_groth16();

    // Attempt verification with an invalid proof (intentionally incomplete: only the first byte).
    let result = crate::Groth16Verifier::verify(
        &proof[..1],
        &public_inputs,
        &vkey_hash,
        &crate::GROTH16_VK_BYTES,
    );

    assert!(
        matches!(result, Err(Groth16Error::GeneralError(Error::InvalidData))),
        "Unexpected error: invalid Groth16 proof verification"
    );
}

#[serial]
#[test]
fn test_verify_plonk() {
    const PLONK_ELF: &[u8] = include_bytes!("../guest-verify-programs/plonk_verify");

    // Setup and generate Plonk proof.
    let (client, proof, public_inputs, vkey_hash) = setup_proof_plonk();

    // Local Plonk verification.
    crate::PlonkVerifier::verify(&proof, &public_inputs, &vkey_hash, &crate::PLONK_VK_BYTES)
        .expect("Plonk proof verification failed");

    // VM verification: send proof, public inputs, and vkey hash to the VM.
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&proof);
    stdin.write_slice(&public_inputs);
    stdin.write(&vkey_hash);

    client.execute(PLONK_ELF, &stdin)
        .run()
        .expect("VM Plonk verification failed");
}

#[serial]
#[test]
fn test_verify_invalid_plonk() {
    // Setup and generate Plonk proof.
    let (_client, proof, public_inputs, vkey_hash) = setup_proof_plonk();

    // Attempt verification with an invalid proof (intentionally incomplete: only the first byte).
    let result = crate::PlonkVerifier::verify(
        &proof[..1],
        &public_inputs,
        &vkey_hash,
        &crate::PLONK_VK_BYTES,
    );

    assert!(
        matches!(result, Err(PlonkError::GeneralError(Error::InvalidData))),
        "Unexpected error: invalid Plonk proof verification"
    );
}

#[serial]
#[test]
fn test_vkeys() {
    let groth16_path = try_install_circuit_artifacts("groth16");
    let s3_vkey_path = groth16_path.join("groth16_vk.bin");
    let s3_vkey_bytes = std::fs::read(s3_vkey_path).expect("Failed to read Groth16 vkey");
    assert_eq!(
        s3_vkey_bytes,
        *crate::GROTH16_VK_BYTES,
        "Groth16 vkey mismatch"
    );

    let plonk_path = try_install_circuit_artifacts("plonk");
    let s3_vkey_path = plonk_path.join("plonk_vk.bin");
    let s3_vkey_bytes = std::fs::read(s3_vkey_path).expect("Failed to read Plonk vkey");
    assert_eq!(
        s3_vkey_bytes,
        *crate::PLONK_VK_BYTES,
        "Plonk vkey mismatch"
    );
}
