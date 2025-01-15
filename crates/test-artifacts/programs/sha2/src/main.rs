#![no_main]
sp1_zkvm::entrypoint!(main);

use hex_literal::hex;
use sha2::{Digest, Sha256};

pub fn main() {
    let hash = Sha256::digest(b"hello world");
    let mut ret = [0u8; 32];
    ret.copy_from_slice(&hash);
    println!("{}", hex::encode(ret));
    assert_eq!(ret, hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));
}
