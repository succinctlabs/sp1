use crate::{error::Error, Groth16Error, PlonkError};
use rstest::rstest;
use serial_test::serial;
use sp1_sdk::{
    install::try_install_circuit_artifacts, CpuProver, Elf, HashableKey, ProveRequest, Prover,
    ProvingKey, SP1Stdin,
};
use test_artifacts::{
    FIBONACCI_BLAKE3_ELF, FIBONACCI_ELF, GROTH16_BLAKE3_ELF, GROTH16_ELF, PLONK_BLAKE3_ELF,
    PLONK_ELF,
};

// TODO: for these tests to work, the `prove_plonk` and `prove_groth16` functions in the SDK
// has to use the proving/verifying keys based on the Aztec SRS by patching the SDK.
// The verification functions in the SDK also has to use the keys based on the Aztec SRS.
#[rstest]
#[case(FIBONACCI_ELF)]
#[case(FIBONACCI_BLAKE3_ELF)]
#[tokio::test]
#[serial]
async fn test_verify_core(#[case] elf: Elf) {
    // Set up the pk and vk.
    let client = CpuProver::new().await;
    let pk = client.setup(elf).await.unwrap();

    // Generate the proof.
    let sp1_proof_with_public_values = client.prove(&pk, SP1Stdin::new()).core().await.unwrap();

    // Verify.
    client
        .verify(&sp1_proof_with_public_values, pk.verifying_key(), None)
        .expect("Proof is invalid");
}

#[rstest]
#[case(FIBONACCI_ELF)]
#[case(FIBONACCI_BLAKE3_ELF)]
#[tokio::test]
#[serial]
async fn test_verify_compressed(#[case] elf: Elf) {
    // Set up the pk and vk.
    let client = CpuProver::new().await;
    let pk = client.setup(elf).await.unwrap();

    // Generate the proof.
    let sp1_proof_with_public_values =
        client.prove(&pk, SP1Stdin::new()).compressed().await.unwrap();

    // Verify.
    client
        .verify(&sp1_proof_with_public_values, pk.verifying_key(), None)
        .expect("Proof is invalid");
}

#[rstest]
#[case(FIBONACCI_ELF)]
#[case(FIBONACCI_BLAKE3_ELF)]
#[tokio::test]
#[serial]
async fn test_verify_groth16(#[case] elf: Elf) {
    // Set up the pk and vk.
    let client = CpuProver::new().await;
    let pk = client.setup(elf).await.unwrap();

    // Generate the proof.
    let sp1_proof_with_public_values = client.prove(&pk, SP1Stdin::new()).groth16().await.unwrap();

    // Verify.
    client
        .verify(&sp1_proof_with_public_values, pk.verifying_key(), None)
        .expect("Proof is invalid");
}

#[rstest]
#[case(FIBONACCI_ELF)]
#[case(FIBONACCI_BLAKE3_ELF)]
#[tokio::test]
#[serial]
async fn test_verify_plonk(#[case] elf: Elf) {
    // Set up the pk and vk.
    let client = CpuProver::new().await;
    let pk = client.setup(elf).await.unwrap();

    // Generate the proof.
    let sp1_proof_with_public_values = client.prove(&pk, SP1Stdin::new()).plonk().await.unwrap();

    // Verify.
    client
        .verify(&sp1_proof_with_public_values, pk.verifying_key(), None)
        .expect("Proof is invalid");
}

#[rstest]
#[case(FIBONACCI_ELF, GROTH16_ELF)]
#[case(FIBONACCI_BLAKE3_ELF, GROTH16_BLAKE3_ELF)]
#[tokio::test]
#[serial]
async fn test_groth16_verifier(#[case] elf: Elf, #[case] groth16_elf: Elf) {
    // Set up the pk and vk.
    let client = CpuProver::new().await;
    let pk = client.setup(elf).await.unwrap();

    // Generate the Groth16 proof.
    let sp1_proof_with_public_values = client.prove(&pk, SP1Stdin::new()).groth16().await.unwrap();

    // Extract the proof and public inputs.
    let proof = sp1_proof_with_public_values.bytes();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

    let vk = pk.verifying_key();

    // Get the vkey hash.
    let vkey_hash = vk.bytes32();
    cfg_if::cfg_if! {
        if #[cfg(feature = "ark")] {
            use ark_bn254::Bn254;
            use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16};
            use crate::{
                decode_sp1_vkey_hash, hash_public_inputs, load_ark_groth16_verifying_key_from_bytes,
                load_ark_proof_from_bytes, load_ark_public_inputs_from_bytes,
            };
            let ark_proof = load_ark_proof_from_bytes(&proof[4 + 32 + 32 + 32..]).unwrap();
            let ark_vkey = load_ark_groth16_verifying_key_from_bytes(&crate::GROTH16_VK_BYTES).unwrap();

            let ark_public_inputs = load_ark_public_inputs_from_bytes(
                &decode_sp1_vkey_hash(&vkey_hash).unwrap(),
                &hash_public_inputs(&public_inputs),
                &proof[4..4 + 32].try_into().unwrap(),
                &proof[4 + 32..4 + 32 + 32].try_into().unwrap(),
                &proof[4 + 32 + 32..4 + 32 + 32 + 32].try_into().unwrap(),
            );
            Groth16::<Bn254, LibsnarkReduction>::verify_proof(&ark_vkey.into(), &ark_proof, &ark_public_inputs)
            .unwrap();
        }
    }

    crate::Groth16Verifier::verify(&proof, &public_inputs, &vkey_hash, &crate::GROTH16_VK_BYTES)
        .expect("Groth16 proof is invalid");

    // Now we should do the verifaction in the VM.
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&proof);
    stdin.write_slice(&public_inputs);
    stdin.write(&vkey_hash);

    let _ = client.execute(groth16_elf, stdin).await.unwrap();
}

#[rstest]
#[case(FIBONACCI_ELF)]
#[case(FIBONACCI_BLAKE3_ELF)]
#[tokio::test]
#[serial]
async fn test_verify_invalid_groth16(#[case] elf: Elf) {
    // Set up the pk and vk.
    let client = CpuProver::new().await;
    let pk = client.setup(elf).await.unwrap();

    // Generate the Groth16 proof.
    let sp1_proof_with_public_values = client.prove(&pk, SP1Stdin::new()).groth16().await.unwrap();

    // Extract the proof and public inputs.
    let proof = sp1_proof_with_public_values.bytes();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

    let vk = pk.verifying_key();

    // Get the vkey hash.
    let vkey_hash = vk.bytes32();
    cfg_if::cfg_if! {
        if #[cfg(feature = "ark")] {
            use ark_bn254::Bn254;
            use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16};
            use crate::{
                decode_sp1_vkey_hash, hash_public_inputs, load_ark_groth16_verifying_key_from_bytes,
                load_ark_proof_from_bytes, load_ark_public_inputs_from_bytes,
            };
            let ark_proof = load_ark_proof_from_bytes(&proof[4 + 32 + 32 + 32..]).unwrap();
            let ark_vkey = load_ark_groth16_verifying_key_from_bytes(&crate::GROTH16_VK_BYTES).unwrap();

            let ark_public_inputs = load_ark_public_inputs_from_bytes(
                &decode_sp1_vkey_hash(&vkey_hash).unwrap(),
                &hash_public_inputs(&public_inputs),
                &proof[4..4 + 32].try_into().unwrap(),
                &proof[4 + 32..4 + 32 + 32].try_into().unwrap(),
                &proof[4 + 32 + 32..4 + 32 + 32 + 32].try_into().unwrap(),
            );
            Groth16::<Bn254, LibsnarkReduction>::verify_proof(&ark_vkey.into(), &ark_proof, &ark_public_inputs)
            .unwrap();
        }
    }

    let result = crate::Groth16Verifier::verify(
        &proof[..1], // Invalid proof (missing the last byte)
        &public_inputs,
        &vkey_hash,
        &crate::GROTH16_VK_BYTES,
    );

    assert!(matches!(result, Err(Groth16Error::GeneralError(Error::InvalidData))));
}

#[rstest]
#[case(FIBONACCI_ELF, PLONK_ELF)]
#[case(FIBONACCI_BLAKE3_ELF, PLONK_BLAKE3_ELF)]
#[tokio::test]
#[serial]
async fn test_plonk_verifier(#[case] elf: Elf, #[case] plonk_elf: Elf) {
    // Set up the pk and vk.
    let client = CpuProver::new().await;
    let pk = client.setup(elf).await.unwrap();

    // Generate the Plonk proof.
    let sp1_proof_with_public_values = client.prove(&pk, SP1Stdin::new()).plonk().await.unwrap();

    // Extract the proof and public inputs.
    let proof = sp1_proof_with_public_values.bytes();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

    let vk = pk.verifying_key();

    // Get the vkey hash.
    let vkey_hash = vk.bytes32();

    crate::PlonkVerifier::verify(&proof, &public_inputs, &vkey_hash, &crate::PLONK_VK_BYTES)
        .expect("Plonk proof is invalid");

    // Now we should do the verifaction in the VM.
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&proof);
    stdin.write_slice(&public_inputs);
    stdin.write(&vkey_hash);

    let _ = client.execute(plonk_elf, stdin).await.unwrap();
}

#[rstest]
#[case(FIBONACCI_ELF)]
#[case(FIBONACCI_BLAKE3_ELF)]
#[tokio::test]
#[serial]
async fn test_verify_invalid_plonk(#[case] elf: Elf) {
    // Set up the pk and vk.
    let client = CpuProver::new().await;
    let pk = client.setup(elf).await.unwrap();

    // Generate the Plonk proof.
    let sp1_proof_with_public_values = client.prove(&pk, SP1Stdin::new()).plonk().await.unwrap();

    // Extract the proof and public inputs.
    let proof = sp1_proof_with_public_values.bytes();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

    let vk = pk.verifying_key();
    // Get the vkey hash.
    let vkey_hash = vk.bytes32();

    let result = crate::PlonkVerifier::verify(
        &proof[..1], // Invalid proof (missing the last byte)
        &public_inputs,
        &vkey_hash,
        &crate::PLONK_VK_BYTES,
    );

    assert!(matches!(result, Err(PlonkError::GeneralError(Error::InvalidData))));
}

#[serial]
#[tokio::test]
async fn test_vkeys() {
    let groth16_path = try_install_circuit_artifacts("groth16")
        .await
        .expect("failed to install groth16 artifacts");
    let s3_vkey_path = groth16_path.join("groth16_vk.bin");
    let s3_vkey_bytes = std::fs::read(s3_vkey_path).expect("failed to read groth16_vk.bin");
    assert_eq!(s3_vkey_bytes, *crate::GROTH16_VK_BYTES);

    let plonk_path =
        try_install_circuit_artifacts("plonk").await.expect("failed to install plonk artifacts");
    let s3_vkey_path = plonk_path.join("plonk_vk.bin");
    let s3_vkey_bytes = std::fs::read(s3_vkey_path).expect("failed to read plonk_vk.bin");
    assert_eq!(s3_vkey_bytes, *crate::PLONK_VK_BYTES);
}
