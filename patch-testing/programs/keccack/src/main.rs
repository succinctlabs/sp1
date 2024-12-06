#![no_main]
sp1_zkvm::entrypoint!(main);

use tiny_keccak::{Hasher, Keccak};

use hex_literal::hex;

/// Emits KECCAK_PERMUTE syscalls.
pub fn main() {
    let input = [1u8; 32];
    let expected_output = hex!("cebc8882fecbec7fb80d2cf4b312bec018884c2d66667c67a90508214bd8bafc");

    let output = keccak256(input);
    assert_eq!(output, expected_output);
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
