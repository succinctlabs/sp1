#![no_main]

use hex_literal::hex;
use sha2::{Digest, Sha256};
use std::hint::black_box;

extern crate curta_zkvm;

curta_zkvm::entrypoint!(main);

fn main() {
    let hash = Sha256::digest(black_box(b"hello world"));
    assert_eq!(
        hash.as_slice(),
        black_box(hex!(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        ))
    );
    println!("hash: {:?}", hash);
}
