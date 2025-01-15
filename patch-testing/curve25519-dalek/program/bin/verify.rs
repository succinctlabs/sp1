#![no_main]
sp1_zkvm::entrypoint!(main);

use ed25519_dalek::{
    Signature, Verifier, VerifyingKey,
};

/// Emits ED_ADD and ED_DECOMPRESS syscalls.
pub fn main() {
    let times = sp1_zkvm::io::read::<usize>();

    for _ in 0..times {
        let (msg, vk, sig) = sp1_zkvm::io::read::<(Vec<u8>, VerifyingKey, Signature)>();

        sp1_zkvm::io::commit(&vk.verify(&msg, &sig).is_ok());
    }
} 
