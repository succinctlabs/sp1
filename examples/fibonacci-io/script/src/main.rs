use sha2::{Digest, Sha256};
use sp1_sdk::{utils, SP1Prover, SP1Stdin, SP1Verifier};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup a tracer for logging.
    utils::setup_tracer();

    // Create an input stream and write '5000' to it.
    let n = 5000u32;

    // The expected result of the fibonacci calculation
    let expected_a = 3867074829u32;
    let expected_b: u32 = 2448710421u32;

    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    println!("wrote to stdin");

    // Generate the proof for the given program and input.
    let mut proof = SP1Prover::prove(ELF, stdin).expect("proving failed");

    println!("generated proof");

    // Read and verify the output.
    let n: u32 = proof.public_values.read::<u32>();
    let a = proof.public_values.read::<u32>();
    let b = proof.public_values.read::<u32>();
    assert_eq!(a, expected_a);
    assert_eq!(b, expected_b);

    println!("a: {}", a);
    println!("b: {}", b);

    // Verify proof and public inputs
    SP1Verifier::verify(ELF, &proof).expect("verification failed");

    let mut pi_hasher = Sha256::new();
    pi_hasher.update(n.to_le_bytes());
    pi_hasher.update(expected_a.to_le_bytes());
    pi_hasher.update(expected_b.to_le_bytes());
    let expected_pi_digest: &[u8] = &pi_hasher.finalize();

    let proof_pi_bytes: Vec<u8> = proof.proof.public_values_digest.into();
    assert_eq!(proof_pi_bytes.as_slice(), expected_pi_digest);

    // Save the proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
