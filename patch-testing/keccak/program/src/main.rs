#![no_main]
sp1_zkvm::entrypoint!(main);

use tiny_keccak::{Hasher, Keccak};

/// Emits KECCAK_PERMUTE syscalls.
pub fn main() {
    let times = sp1_zkvm::io::read::<usize>();

    for _ in 0..times {
        let preimage = sp1_zkvm::io::read_vec();
        let result = keccak256(preimage);

        sp1_zkvm::io::commit(&result);
    } 
}

/// Simple interface to the [`keccak256`] hash function.
///
/// [`keccak256`]: https://en.wikipedia.org/wiki/SHA-3
pub fn keccak256<T: AsRef<[u8]>>(bytes: T) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes.as_ref());
    hasher.finalize(&mut output);
    output
}
