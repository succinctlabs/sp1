//! This is a test program that takes in a sp1_core vkey and a list of inputs, and then verifies the
//! SP1 proof for each input.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};
use sp1_zkvm::precompiles::verify::verify_sp1_proof;

fn words_to_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let word_bytes = words[i].to_le_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    bytes
}

pub fn main() {
    let vkey = sp1_zkvm::io::read::<[u32; 8]>();
    println!("Read vkey: {:?}", hex::encode(words_to_bytes(&vkey)));
    let inputs = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    inputs.iter().for_each(|input| {
        // Get expected pv_digest hash: sha256(input)
        let pv_digest = Sha256::digest(input);
        verify_sp1_proof(&vkey, &pv_digest.into());

        println!("Verified proof for digest: {:?}", hex::encode(pv_digest));
        println!("Verified input: {:?}", hex::encode(input));
    });
}
