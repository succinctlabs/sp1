#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2_v0_9_8::{Digest as D1, Sha256 as Sha256_9_8};
use sha2_v0_10_8::{Digest as D2, Sha256 as Sha256_10_8};
use zeroize::Zeroize;

fn main() {
    let times = sp1_zkvm::io::read::<usize>();
    let times = times.clamp(1, 1000);

    for _ in 0..times {
        let mut preimage = sp1_zkvm::io::read_vec();
        if preimage.len() > 1024 * 1024 {
            preimage.truncate(1024 * 1024);
        }

        let (hash_v9, hash_v10) = compute_hashes(&preimage);

        assert!(
            hash_v9[..] == hash_v10[..],
            "SHA-256 version mismatch detected"
        );

        preimage.zeroize();

        sp1_zkvm::io::commit(&hash_v9);
    }
}

fn compute_hashes(data: &[u8]) -> ([u8; 32], [u8; 32]) {
    // v0.9.8 Hash
    let mut hasher_v9 = Sha256_9_8::new();
    hasher_v9.update(data);
    let hash_v9: [u8; 32] = hasher_v9.finalize().into();

    // v0.10.8 Hash
    let mut hasher_v10 = Sha256_10_8::new();
    hasher_v10.update(data);
    let hash_v10: [u8; 32] = hasher_v10.finalize().into();

    if subtle::ConstantTimeEq::ct_eq(&hash_v9[..], &hash_v10[..]).unwrap_u8() != 1 {
        panic!("Hash mismatch detected");
    }

    (hash_v9, hash_v10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        let input = vec![];
        let (h1, h2) = compute_hashes(&input);
        assert_eq!(h1, h2);
    }
}
