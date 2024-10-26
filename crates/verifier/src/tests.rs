use sp1_sdk::{HashableKey, ProverClient, SP1Stdin};

extern crate std;

#[test]
fn test_verify_groth16() {
    let client = ProverClient::new();
    let elf = include_bytes!("../../../tests/fibonacci/elf/riscv32im-succinct-zkvm-elf");
    let (pk, vk) = client.setup(elf);
    let mut stdin = SP1Stdin::new();
    stdin.write(&10usize);

    // Generate proof & verify.
    let sp1_proof_with_public_values = client.prove(&pk, stdin).groth16().run().unwrap();

    let proof = sp1_proof_with_public_values.bytes();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();
    let vkey_hash = vk.bytes32();

    let is_valid = crate::Groth16Verifier::verify(
        &proof,
        &public_inputs,
        &vkey_hash,
        &crate::GROTH16_VK_BYTES,
    )
    .expect("Groth16 proof is invalid");

    if !is_valid {
        panic!("Groth16 proof is invalid");
    }
}

#[cfg(feature = "getrandom")]
#[test]
fn test_verify_plonk() {
    let client = ProverClient::new();
    let elf = include_bytes!("../../../tests/fibonacci/elf/riscv32im-succinct-zkvm-elf");
    let (pk, vk) = client.setup(elf);
    let mut stdin = SP1Stdin::new();
    stdin.write(&10usize);

    // Generate proof & verify.
    let sp1_proof_with_public_values = client.prove(&pk, stdin).plonk().run().unwrap();

    let proof = sp1_proof_with_public_values.raw_with_checksum();
    let public_inputs = sp1_proof_with_public_values.public_values.to_vec();

    // This vkey hash was derived by calling `vk.bytes32()` on the verifying key.
    let vkey_hash = vk.bytes32();

    let is_valid =
        crate::PlonkVerifier::verify(&proof, &public_inputs, &vkey_hash, &crate::PLONK_VK_BYTES)
            .expect("Plonk proof is invalid");

    if !is_valid {
        panic!("Plonk proof is invalid");
    }
}
