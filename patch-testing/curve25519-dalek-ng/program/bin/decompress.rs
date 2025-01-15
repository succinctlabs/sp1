#![no_main]
sp1_zkvm::entrypoint!(main);

use curve25519_dalek_ng::edwards::CompressedEdwardsY;

/// Emits ED_DECOMPRESS syscall.
fn main() {
    // non-canonical point
    let mut bytes: [u8; 32] = [0; 32];
    for i in 0..32 {
        bytes[i] = 255;
    }
    bytes[0] = 253;
    bytes[31] = 127;
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());

    // y = 0 with sign off
    let mut bytes: [u8; 32] = [0; 32];
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());

    // y = 0 with sign on
    let mut bytes: [u8; 32] = [0; 32];
    bytes[31] = 128;
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());

    // x = 0 with sign off
    let mut bytes: [u8; 32] = [0; 32];
    bytes[0] = 1;
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());

    // x = 0 with sign on
    let mut bytes: [u8; 32] = [0; 32];
    bytes[0] = 1;
    bytes[31] = 128;
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());

    // x = 0 with sign off
    let mut bytes: [u8; 32] = [255u8; 32];
    bytes[0] = 255 - 19;
    bytes[31] = 127;
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());

    // x = 0 with sign on
    let mut bytes: [u8; 32] = [255u8; 32];
    bytes[0] = 255 - 19;
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());
}
