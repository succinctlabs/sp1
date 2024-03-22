//! A simple script to generate and verify the proof of a given program.

use sp1_core::{SP1Prover, SP1Stdin, SP1Verifier};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    let start = std::time::Instant::now();
    // Generate proof.
    let mut stdin = SP1Stdin::new();
    let count = 64u64;
    stdin.write(&count);
    let mut proof = SP1Prover::prove(ELF, stdin).expect("proving failed");

    // Read output.
    let count = proof.stdout.read::<u64>();
    println!("count: {}", count);
    let end = std::time::Instant::now();
    println!("Proof generation time: {:?}", end.duration_since(start));

    // Verify proof.
    SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
