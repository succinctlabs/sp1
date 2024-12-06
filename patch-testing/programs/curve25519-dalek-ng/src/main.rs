#![no_main]
sp1_zkvm::entrypoint!(main);

use curve25519_dalek_ng::edwards::CompressedEdwardsY as CompressedEdwardsY_dalek_ng;

/// Emits ED_DECOMPRESS syscall.
pub fn main() {
    let input = [1u8; 32];
    let y = CompressedEdwardsY_dalek_ng(input);

    println!("cycle-tracker-start: curve25519-dalek-ng decompress");
    let decompressed_key = y.decompress();
    println!("cycle-tracker-end: curve25519-dalek-ng decompress");

    let compressed_key = decompressed_key.unwrap().compress();
    assert_eq!(compressed_key, y);
}


// todo add test for fail decompression, probably need to change patch
