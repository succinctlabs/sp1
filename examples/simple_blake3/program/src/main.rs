//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let chunk = [1u8; 1024];
    let mut hasher = blake3::Hasher::new();
    println!("cycle-tracker-start: hash");
    hasher.update(&chunk);
    hasher.finalize();
    println!("cycle-tracker-end: hash");
}
