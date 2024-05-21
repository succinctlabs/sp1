//! A program that takes a number `n` as input, and writes if `n` is prime as an output.
use sp1_sdk::{utils, ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup a tracer for logging.
    utils::setup_logger();

    let mut stdin = SP1Stdin::new();

    // Create an input stream and write '29' to it
    let n = 29u64;
    stdin.write(&n);

    // Generate and verify the proof
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).unwrap();

    let is_prime = proof.public_values.read::<bool>();
    println!("Is 29 prime? {}", is_prime);

    client.verify(&proof, &vk).expect("verification failed");

    // Save the proof
    proof
        .save("proof-with-is-prime.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
