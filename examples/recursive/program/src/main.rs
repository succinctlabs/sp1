//! A simple program that takes a sequence of numbers as input, cubic all of them, and then sum up.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use recursive_lib::{acc_cubic, verify_proof, CircuitInput, utils::sha256_hash};

pub fn main() {
    // 1) Read program input 
    // Read prover's sequence number
    let seq = sp1_zkvm::io::read::<u32>();
    // Read hash of vkey for verifying last prover's proof
    let vkey_u32_hash = sp1_zkvm::io::read::<[u32; 8]>();
    // Read circuit input
    let circuit_input = sp1_zkvm::io::read::<CircuitInput>();

    // 2) Verify last prover's proof with the help of:
    //      a) last prover's result 
    //      b) public input of acc_cubic function,
    //     and generate a recursive hash of all public values of acc_cubic to avoid commit long public inputs
    let hash_right = sha256_hash(&circuit_input.public_value.to_le_bytes());
    let public_input_hash = if seq != 0 {
        verify_proof(&vkey_u32_hash, &circuit_input.public_input_hash, circuit_input.private_value);
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&circuit_input.public_input_hash);
        bytes.extend_from_slice(&hash_right);
        sha256_hash(&bytes)
    } else {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend(&hash_right);
        sha256_hash(&bytes)
    };

    // 3) Do acc_cubic computation once last prover's reuslt has been verified with proof
    let result = acc_cubic(circuit_input.public_value, circuit_input.private_value);

    // 4) Commit the recursive public input hash and acc_cubic result
    sp1_zkvm::io::commit(&public_input_hash);
    sp1_zkvm::io::commit(&result);
}
