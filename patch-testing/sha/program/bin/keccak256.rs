#![no_main]
sp1_zkvm::entrypoint!(main);

use sha3::{Digest, Keccak256};

pub fn main() {
    let count = sp1_zkvm::io::read::<usize>();
    for _ in 0..count {
        let input = sp1_zkvm::io::read_vec();
        let digest: [u8; 32] = Keccak256::digest(&input).into();
        sp1_zkvm::io::commit(&digest);
    }
}
