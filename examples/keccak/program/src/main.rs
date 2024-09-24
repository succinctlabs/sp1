
//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use tiny_keccak::{Hasher, Keccak};

pub fn main() {
    // Create an input stream and write '500' to it.
    let n = sp1_zkvm::io::read::<String>();
    let mut keccak_hasher = Keccak::v256();
    let mut output = [0; 32];
    keccak_hasher.update(n.as_bytes());
    keccak_hasher.finalize(&mut output);
    sp1_zkvm::io::commit_slice(&output);
}