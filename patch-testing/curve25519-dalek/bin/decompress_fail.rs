#![no_main]
sp1_zkvm::entrypoint!(main);

use curve25519_dalek::edwards::CompressedEdwardsY;

/// Emits ED_DECOMPRESS syscall.
fn main() {
    let input_passing = [1u8; 32];

    // This y-coordinate is not square, and therefore not on the curve
    let limbs: [u64; 4] =
        [8083970408152925034, 11907700107021980321, 16259949789167878387, 5645861033211660086];

    // convert to bytes
    let input_failing: [u8; 32] =
        limbs.iter().flat_map(|l| l.to_be_bytes()).collect::<Vec<u8>>().try_into().unwrap();

    let y_passing = CompressedEdwardsY(input_passing);

    println!("cycle-tracker-start: curve25519-dalek decompress");
    let decompressed_key = y_passing.decompress().unwrap();
    println!("cycle-tracker-end: curve25519-dalek decompress");

    let compressed_key = decompressed_key.compress();
    assert_eq!(compressed_key, y_passing);

    let y_failing = CompressedEdwardsY(input_failing);
    println!("cycle-tracker-start: curve25519-dalek decompress");
    let decompressed_key = y_failing.decompress();
    println!("cycle-tracker-end: curve25519-dalek decompress");

    assert!(decompressed_key.is_none());
}
