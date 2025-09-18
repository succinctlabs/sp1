use rstest::rstest;
use serial_test::serial;
use sp1_sdk::{install::try_install_circuit_artifacts, HashableKey, ProverClient, SP1Stdin};
use test_artifacts::{
    FIBONACCI_BLAKE3_ELF, FIBONACCI_ELF, GROTH16_BLAKE3_ELF, GROTH16_COMPRESSED_BLAKE3_ELF,
    GROTH16_COMPRESSED_ELF, GROTH16_ELF, PLONK_BLAKE3_ELF, PLONK_ELF,
};

use crate::{error::Error, Groth16Error, PlonkError};

#[rstest]
#[case(FIBONACCI_ELF)]
#[case(FIBONACCI_BLAKE3_ELF)]
#[serial]
fn test_verify_core(#[case] elf: &[u8]) {
    // Set up the pk and vk.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(elf);

    // Generate the proof.
    let sp1_proof_with_public_values = client.prove(&pk, &SP1Stdin::new()).core().run().unwrap();

    // Verify.
    client.verify(&sp1_proof_with_public_values, &vk).expect("Proof is invalid");
}

#[rstest]
#[case(FIBONACCI_ELF)]
#[case(FIBONACCI_BLAKE3_ELF)]
#[serial]
fn test_verify_compressed(#[case] elf: &[u8]) {
    // Set up the pk and vk.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(elf);

    // Generate the proof.
    let sp1_proof_with_public_values =
        client.prove(&pk, &SP1Stdin::new()).compressed().run().unwrap();

    // Verify.
    client.verify(&sp1_proof_with_public_values, &vk).expect("Proof is invalid");
}

#[rstest]
#[case(FIBONACCI_ELF)]
#[case(FIBONACCI_BLAKE3_ELF)]
#[serial]
fn test_verify_groth16(#[case] elf: &[u8]) {
    // Set up the pk and vk.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(elf);

    // Generate the proof.
    let sp1_proof_with_public_values = client.prove(&pk, &SP1Stdin::new()).groth16().run().unwrap();

    // Verify.
    client.verify(&sp1_proof_with_public_values, &vk).expect("Proof is invalid");
}

#[rstest]
#[case(FIBONACCI_ELF)]
#[case(FIBONACCI_BLAKE3_ELF)]
#[serial]
fn test_verify_plonk(#[case] elf: &[u8]) {
    // Set up the pk and vk.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(elf);

    // Generate the proof.
    let sp1_proof_with_public_values = client.prove(&pk, &SP1Stdin::new()).plonk().run().unwrap();

    // Verify.
    client.verify(&sp1_proof_with_public_values, &vk).expect("Proof is invalid");
}

#[rstest]
#[case(FIBONACCI_ELF, GROTH16_COMPRESSED_ELF)]
#[case(FIBONACCI_BLAKE3_ELF, GROTH16_COMPRESSED_BLAKE3_ELF)]
#[serial]
fn test_groth16_verifier_compressed(#[case] elf: &[u8], #[case] groth16_compressed_elf: &[u8]) {
    // Set up the pk and vk.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(elf);

    // Generate the Groth16 proof.
    let sp1_proof_with_public_values = client.prove(&pk, &SP1Stdin::new()).groth16().run().unwrap();

    // Extract the proof and public inputs.
    let proof = sp1_proof_with_public_values.bytes();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

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
            let ark_proof = load_ark_proof_from_bytes(&proof[4..]).unwrap();
            let ark_vkey = load_ark_groth16_verifying_key_from_bytes(&crate::GROTH16_VK_BYTES).unwrap();

            let ark_public_inputs = load_ark_public_inputs_from_bytes(
                &decode_sp1_vkey_hash(&vkey_hash).unwrap(),
                &hash_public_inputs(&public_inputs),
            );
            Groth16::<Bn254, LibsnarkReduction>::verify_proof(&ark_vkey.into(), &ark_proof, &ark_public_inputs)
            .unwrap();
        }
    }

    // Verify compressed Groth16 proof outside of VM.
    let compressed_proof = crate::compress_groth16_proof_from_bytes(&proof[4..]).unwrap();
    let decompressed_proof = crate::decompress_groth16_proof_from_bytes(&compressed_proof).unwrap();
    assert_eq!(decompressed_proof, proof[4..], "Decompressed proof does not match original proof");
    let mut new_proof = [0u8; 4 + crate::constants::COMPRESSED_GROTH16_PROOF_LENGTH];
    new_proof[..4].copy_from_slice(&proof[..4]);
    new_proof[4..].copy_from_slice(&compressed_proof);

    crate::Groth16Verifier::verify_compressed(
        &new_proof,
        &public_inputs,
        &vkey_hash,
        &crate::GROTH16_VK_BYTES,
    )
    .expect("Compressed Groth16 proof is invalid");

    // Now we should do the verifaction in the VM.
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&new_proof);
    stdin.write_slice(&public_inputs);
    stdin.write(&vkey_hash);

    let _ = client.execute(groth16_compressed_elf, &stdin).run().unwrap();
}

#[rstest]
#[case(FIBONACCI_ELF, GROTH16_ELF)]
#[case(FIBONACCI_BLAKE3_ELF, GROTH16_BLAKE3_ELF)]
#[serial]
fn test_groth16_verifier(#[case] elf: &[u8], #[case] groth16_elf: &[u8]) {
    // Set up the pk and vk.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(elf);

    // Generate the Groth16 proof.
    let sp1_proof_with_public_values = client.prove(&pk, &SP1Stdin::new()).groth16().run().unwrap();

    // Extract the proof and public inputs.
    let proof = sp1_proof_with_public_values.bytes();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

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
            let ark_proof = load_ark_proof_from_bytes(&proof[4..]).unwrap();
            let ark_vkey = load_ark_groth16_verifying_key_from_bytes(&crate::GROTH16_VK_BYTES).unwrap();

            let ark_public_inputs = load_ark_public_inputs_from_bytes(
                &decode_sp1_vkey_hash(&vkey_hash).unwrap(),
                &hash_public_inputs(&public_inputs),
            );
            Groth16::<Bn254, LibsnarkReduction>::verify_proof(&ark_vkey.into(), &ark_proof, &ark_public_inputs)
            .unwrap();
        }
    }

    // Verify the compressed groth16 proof as well.
    let compressed_proof = crate::compress_groth16_proof_from_bytes(&proof[4..]).unwrap();
    let decompressed_proof = crate::decompress_groth16_proof_from_bytes(&compressed_proof).unwrap();
    assert_eq!(decompressed_proof, proof[4..], "Decompressed proof does not match original proof");
    let mut new_proof = [0u8; 4 + crate::constants::COMPRESSED_GROTH16_PROOF_LENGTH];
    new_proof[..4].copy_from_slice(&proof[..4]);
    new_proof[4..].copy_from_slice(&compressed_proof);

    crate::Groth16Verifier::verify_compressed(
        &new_proof,
        &public_inputs,
        &vkey_hash,
        &crate::GROTH16_VK_BYTES,
    )
    .expect("Compressed Groth16 proof is invalid");

    // Verify the original groth16 proof outside of the VM.
    crate::Groth16Verifier::verify(&proof, &public_inputs, &vkey_hash, &crate::GROTH16_VK_BYTES)
        .expect("Groth16 proof is invalid");

    // Now we should do the verifaction in the VM.
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&proof);
    stdin.write_slice(&public_inputs);
    stdin.write(&vkey_hash);

    let _ = client.execute(groth16_elf, &stdin).run().unwrap();
}

#[rstest]
#[case(FIBONACCI_ELF)]
#[case(FIBONACCI_BLAKE3_ELF)]
#[serial]
fn test_verify_invalid_groth16(#[case] elf: &[u8]) {
    // Set up the pk and vk.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(elf);

    // Generate the Groth16 proof.
    let sp1_proof_with_public_values = client.prove(&pk, &SP1Stdin::new()).groth16().run().unwrap();

    // Extract the proof and public inputs.
    let proof = sp1_proof_with_public_values.bytes();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

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
            let ark_proof = load_ark_proof_from_bytes(&proof[4..]).unwrap();
            let ark_vkey = load_ark_groth16_verifying_key_from_bytes(&crate::GROTH16_VK_BYTES).unwrap();

            let ark_public_inputs = load_ark_public_inputs_from_bytes(
                &decode_sp1_vkey_hash(&vkey_hash).unwrap(),
                &hash_public_inputs(&public_inputs),
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
#[serial]
fn test_plonk_verifier(#[case] elf: &[u8], #[case] plonk_elf: &[u8]) {
    // Set up the pk and vk.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(elf);

    // Generate the Plonk proof.
    let sp1_proof_with_public_values = client.prove(&pk, &SP1Stdin::new()).plonk().run().unwrap();

    // Extract the proof and public inputs.
    let proof = sp1_proof_with_public_values.bytes();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

    // Get the vkey hash.
    let vkey_hash = vk.bytes32();

    crate::PlonkVerifier::verify(&proof, &public_inputs, &vkey_hash, &crate::PLONK_VK_BYTES)
        .expect("Plonk proof is invalid");

    // Now we should do the verifaction in the VM.
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&proof);
    stdin.write_slice(&public_inputs);
    stdin.write(&vkey_hash);

    let _ = client.execute(plonk_elf, &stdin).run().unwrap();
}

#[rstest]
#[case(FIBONACCI_ELF)]
#[case(FIBONACCI_BLAKE3_ELF)]
#[serial]
fn test_verify_invalid_plonk(#[case] elf: &[u8]) {
    // Set up the pk and vk.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(elf);

    // Generate the Plonk proof.
    let sp1_proof_with_public_values = client.prove(&pk, &SP1Stdin::new()).plonk().run().unwrap();

    // Extract the proof and public inputs.
    let proof = sp1_proof_with_public_values.bytes();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

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
