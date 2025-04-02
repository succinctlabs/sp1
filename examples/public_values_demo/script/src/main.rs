use serde::{Deserialize, Serialize};
use sp1_core::{SP1Prover, SP1Stdin, SP1Verifier};
use sp1_primitives::io::SP1PublicValues;

#[derive(Debug, Serialize, Deserialize)]
struct ProgramOutput {
    value: u32,
    message: String,
}

fn main() {
    // Setup a simple program that will be verified by our demo
    let program_path = "../../../target/release/sp1-public-values-demo";

    // Create an initial output
    let initial_output = ProgramOutput { value: 42, message: "Hello, SP1!".to_string() };

    // Serialize the output to public values
    let mut public_values = SP1PublicValues::new();
    public_values.write(&initial_output);

    // Create the prover and prove the execution
    println!("Generating proof for first program...");
    let mut stdin = SP1Stdin::new();
    let prover = SP1Prover::new(program_path).unwrap();
    let proof = prover.prove_stdin(stdin).unwrap();

    // Verify the proof
    println!("Verifying proof...");
    let verifier = SP1Verifier::new(program_path).unwrap();
    verifier.verify(proof.clone()).unwrap();

    // Now prepare input for our demo program that uses the new API
    println!("Preparing input for demo program...");

    // Create stdin for demo program - send the proof's public values
    // and the program identifier
    let mut demo_stdin = SP1Stdin::new();
    demo_stdin.write(&proof.public_values);
    demo_stdin.write(&proof.program_digest.0);

    // Create the prover for the demo program and prove the execution
    println!("Generating proof for demo program...");
    let demo_prover = SP1Prover::new(program_path).unwrap();
    let demo_proof = demo_prover.prove_stdin(demo_stdin).unwrap();

    // Verify the demo proof
    println!("Verifying demo proof...");
    let demo_verifier = SP1Verifier::new(program_path).unwrap();
    demo_verifier.verify(demo_proof.clone()).unwrap();

    // Read the output from the demo program
    println!("Reading output from demo program...");
    let mut public_values_copy = demo_proof.public_values.clone();
    let final_output: ProgramOutput = public_values_copy.read();

    // Display the result
    println!("Demo program output: {:?}", final_output);

    println!("Successfully demonstrated SP1PublicValues API!");
}
