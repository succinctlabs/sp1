use serial_test::serial;
use sp1_sdk::{install::try_install_circuit_artifacts, HashableKey, ProverClient, SP1Stdin};

cfg_if::cfg_if! {
    if #[cfg(feature = "blake3")] {
        use test_artifacts::FIBONACCI_BLAKE3_ELF as FIBONACCI_ELF;
    }
    else {
        use test_artifacts::FIBONACCI_ELF;
    }
}

use crate::{error::Error, Groth16Error, PlonkError};

#[serial]
#[test]
fn test_verify_groth16() {
    #[cfg(feature = "blake3")]
    const GROTH16_ELF: &[u8] = include_bytes!("../guest-verify-programs/groth16_verify_blake3");
    #[cfg(not(feature = "blake3"))]
    const GROTH16_ELF: &[u8] = include_bytes!("../guest-verify-programs/groth16_verify");

    // Set up the pk and vk.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(FIBONACCI_ELF);

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

    crate::Groth16Verifier::verify(&proof, &public_inputs, &vkey_hash, &crate::GROTH16_VK_BYTES)
        .expect("Groth16 proof is invalid");

    // Now we should do the verifaction in the VM.
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&proof);
    stdin.write_slice(&public_inputs);
    stdin.write(&vkey_hash);

    let _ = client.execute(GROTH16_ELF, &stdin).run().unwrap();
}

#[serial]
#[test]
fn test_verify_invalid_groth16() {
    // Set up the pk and vk.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(FIBONACCI_ELF);

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

#[serial]
#[test]
fn test_verify_plonk() {
    #[cfg(feature = "blake3")]
    const PLONK_ELF: &[u8] = include_bytes!("../guest-verify-programs/plonk_verify_blake3");
    #[cfg(not(feature = "blake3"))]
    const PLONK_ELF: &[u8] = include_bytes!("../guest-verify-programs/plonk_verify");

    // Set up the pk and vk.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(FIBONACCI_ELF);

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

    let _ = client.execute(PLONK_ELF, &stdin).run().unwrap();
}

#[serial]
#[test]
fn test_verify_invalid_plonk() {
    // Set up the pk and vk.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(FIBONACCI_ELF);

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
