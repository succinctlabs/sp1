#![no_main]
sp1_zkvm::entrypoint!(main);

use sha3::Digest;

/// Emits SHA_COMPRESS and SHA_EXTEND syscalls.
pub fn main() {
    let times = sp1_zkvm::io::read::<usize>();
    
    for _ in 0..times {
        let preimage = sp1_zkvm::io::read_vec();

        let mut sha3 = sha3::Sha3_256::new();

        sha3.update(&preimage);

        let digest: [u8; 32] = sha3.finalize().into();

        sp1_zkvm::io::commit(&digest);
    }
}
