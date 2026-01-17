use sp1_sdk::{include_elf, utils, ProverClient, SP1Stdin};

// Le nom doit correspondre exactement au package name dans program/Cargo.toml
const ELF: &[u8] = include_elf!("poseidon2-program");

fn main() {
    utils::setup_logger();

    // 1. Setup the input
    let n = 42u64;
    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    println!("Generating proof for input: {}", n);

    // 2. Generate the proof
    let client = ProverClient::from_env();

    // Setup verification keys
    let (pk, vk) = client.setup(ELF);

    // CORRECTION ICI : Ajout de 'mut' car .read() modifie l'état interne
    let mut proof = client.prove(&pk, &stdin).run().expect("failed to prove");

    // 3. Verify the proof
    client.verify(&proof, &vk).expect("verification failed");

    // 4. Read the output
    let hash = proof.public_values.read::<u64>();
    println!("Success! Result in Goldilocks field: {}", hash);

    // 5. Integrity Check
    // We assert that the hash matches the expected value from our optimized implementation.
    // This acts as a regression test to ensure logic stability.
    let expected_hash = 10991303467715180827;
    assert_eq!(
        hash, expected_hash,
        "CRITICAL ERROR: Hash mismatch! The logic behaves differently than expected."
    );
}
