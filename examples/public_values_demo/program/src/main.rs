//! Demo showing the usage of SP1PublicValues API for aggregation proofs.

#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};
use sp1_zkvm::SP1PublicValues;

// Example program output structure
#[derive(Debug, Serialize, Deserialize)]
struct ProgramOutput {
    value: u32,
    message: String,
}

pub fn main() {
    // Read a SP1PublicValues object directly from the input
    let mut proof_public_values: SP1PublicValues = sp1_zkvm::io::read();

    // Get the hash for verification - use the existing hash() method
    // and convert it to the expected format
    let hash = proof_public_values.hash();
    let pv_digest: [u8; 32] = hash.try_into().expect("Hash should be 32 bytes");

    // Read the program identifier (verification key digest)
    let program_identifier = sp1_zkvm::io::read::<[u32; 8]>();

    // Verify the proof using the hash
    sp1_zkvm::lib::verify::verify_sp1_proof(&program_identifier, &pv_digest);

    // Extract the program output from the public values
    // Create a copy to avoid modifying the original
    let mut public_values_copy = proof_public_values.clone();
    let program_output: ProgramOutput = public_values_copy.read();

    // Use the program output
    let new_value = program_output.value * 2;
    let new_message = format!("Processed: {}", program_output.message);

    // Create the final output
    let final_output = ProgramOutput { value: new_value, message: new_message };

    // Commit the result to public values
    sp1_zkvm::io::commit(&final_output);
}
