//! A simple program to be proven inside the zkVM.

#![no_main]
curta_zkvm::entrypoint!(main);

use blake3;

pub fn main() {
    let a : u32 = 0;
    let bytes = a.to_le_bytes();
    let hash = blake3::hash(&bytes);
}
