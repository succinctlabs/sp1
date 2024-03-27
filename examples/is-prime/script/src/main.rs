//! A program that takes a number `n` as input, and writes if `n` is prime as an output.
use sp1_core::{utils, SP1Prover, SP1Stdin, SP1Verifier};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup a tracer for logging.
    utils::setup_tracer();

    let mut stdin = SP1Stdin::new();

    // Create an input stream and write '29' to it
    let n = 29u64;
    stdin.write(&n);

    // Generate and verify the proof
    let mut proof = SP1Prover::prove(ELF, stdin).expect("proving failed");
    let is_prime = proof.stdout.read::<bool>();
    println!("Is 29 prime? {}", is_prime);

    SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // Save the proof
    proof
        .save("proof-with-is-prime.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
