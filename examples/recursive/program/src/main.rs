//! A simple program that takes a sequence of numbers as input, cubic all of them, and then sum up. 

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use recursive_lib::{cubic, verify_proof, merkle_tree_public_input, CircuitInput};

pub fn main() {
    // Read prover's sequence number
    let seq = sp1_zkvm::io::read::<u32>();
    // Read hash of vkey for verifying last prover's proof
    let vkey_u32_hash = sp1_zkvm::io::read::<[u32; 8]>();
    // Read circuit input
    let circuit_input = sp1_zkvm::io::read::<CircuitInput>();

    // Do cubic computation
    let result = cubic(circuit_input.public_value);
    // Verify proof output by last prover 
    if seq != 0 {
        verify_proof(&vkey_u32_hash, &circuit_input.public_input_merkle_root);
    }
    // Construct a merkle root of all public inputs
    let merkle_root = merkle_tree_public_input(
        circuit_input.witness,
        circuit_input.public_value,
    );

    // Commit this merkle root and cubic result
    sp1_zkvm::io::commit(&merkle_root);
    sp1_zkvm::io::commit(&result);
}
