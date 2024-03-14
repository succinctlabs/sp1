//! A simple script to generate and verify the proof of a given program.

use sp1_core::{SP1Prover, SP1Stdin, SP1Verifier};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
    let mut stdin = SP1Stdin::new();
    let vec_1 = vec![1, 2, 3];
    let vec_2 = vec![4, 5, 6];
    let threshold = 100;
    stdin.write(&vec_1);
    stdin.write(&vec_2);
    stdin.write(&threshold);
    let mut proof = SP1Prover::prove(ELF, stdin).expect("proving failed");

    // Read output.
    let sum_of_diffs_squared = proof.stdout.read::<u128>();

    println!("======================================");
    println!("sum_of_diffs_squared: {}", sum_of_diffs_squared);
    // Verify proof.
    SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
