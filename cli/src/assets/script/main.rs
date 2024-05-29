//! A simple script to generate and verify the proof of a given program.

use sp1_sdk::{utils, ProverClient, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup logging.
    utils::setup_logger();

    // Generate proof.
    let mut stdin = SP1Stdin::new();
    let n = 186u32;
    stdin.write(&n);
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove_compressed(&pk, stdin).expect("proving failed");

    // Read output.
    let a = proof.public_values.read::<u128>();
    let b = proof.public_values.read::<u128>();
    println!("a: {}", a);
    println!("b: {}", b);

    // Verify proof.
    client
        .verify_compressed(&proof, &vk)
        .expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
