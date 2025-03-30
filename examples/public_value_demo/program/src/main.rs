//! Demo showing the usage of SP1PublicValues API for aggregation proofs.

#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};

// Example program output structure
#[derive(Debug, Serialize, Deserialize)]
struct ProgramOutput {
    value: u32,
    message: String,
}

pub fn main() {
    // Read a SP1PublicValues object directly from the input
    let proof: sp1_zkvm::SP1PublicValues = sp1_zkvm::io::read();

    // Get the digest for verification
    let pv_digest = proof.digest();

    // Read the program identifier (verification key digest)
    let program_identifier = sp1_zkvm::io::read::<[u32; 8]>();

    // Verify the proof using the digest
    sp1_zkvm::lib::verify::verify_sp1_proof(&program_identifier, &pv_digest);

    // Extract the program output directly from the public values
    let program_output: ProgramOutput = proof.output();

    // Use the program output
    let new_value = program_output.value * 2;
    let new_message = format!("Processed: {}", program_output.message);

    // Create the final output
    let final_output = ProgramOutput { value: new_value, message: new_message };

    // Commit the result to public values
    sp1_zkvm::io::commit(&final_output);
}
