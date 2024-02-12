//! A simple script to generate and verify the proof of a given program.

use curta_core::{CurtaProver, CurtaStdin, CurtaVerifier};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-curta-zkvm-elf");

fn main() {
    // Generate proof.
    let mut stdin = CurtaStdin::new();
    stdin.write(&5000u32);
    let mut proof = CurtaProver::prove(ELF, stdin).expect("proving failed");

    // Read output.
    let a = proof.stdout.read::<u32>();
    let b = proof.stdout.read::<u32>();
    println!("a: {}", a);
    println!("b: {}", b);

    // Verify proof.
    CurtaVerifier::verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
