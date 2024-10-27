//! A script that generates a Groth16 proof for the Fibonacci program, and verifies the
//! Groth16 proof in SP1.

use sp1_sdk::{include_elf, utils, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin};

/// The ELF for the Groth16 verifier program.
const GROTH16_ELF: &[u8] = include_elf!("groth16-verifier-program");

/// The ELF for the Fibonacci program.
const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

fn generate_fibonacci_proof() -> (SP1ProofWithPublicValues, String) {
    // Create an input stream and write '20' to it.
    let n = 20u32;

    // The input stream that the program will read from using `sp1_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    // Create a `ProverClient`.
    let client = ProverClient::new();

    // Generate the proof for the fibonacci program..
    let (pk, vk) = client.setup(FIBONACCI_ELF);
    println!("vk: {:?}", vk.bytes32());
    (client.prove(&pk, stdin).groth16().run().unwrap(), vk.bytes32())
}

fn main() {
    // Setup logging.
    utils::setup_logger();

    // Generate the Fibonacci proof.
    let (fibonacci_proof, vk) = generate_fibonacci_proof();

    // Write the proof, public values, and vkey hash to the input stream.
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(fibonacci_proof.bytes());
    stdin.write_vec(fibonacci_proof.public_values.to_vec());
    stdin.write(&vk);

    // Create a `ProverClient`.
    let client = ProverClient::new();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(GROTH16_ELF, stdin.clone()).run().unwrap();
    println!("executed groth16 program with {} cycles", report.total_instruction_count());
    println!("{}", report);
}
