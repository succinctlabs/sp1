#![no_main]
sp1_zkvm::entrypoint!(main);

use curve25519_dalek_ng::edwards::CompressedEdwardsY;

/// Emits ED_DECOMPRESS syscall.
fn main() {
    let mut bytes1: [u8; 32] = [0; 32];
    for i in 0..32 {
        bytes1[i] = 0;
    }
    let mut bytes2: [u8; 32] = [0; 32];
    for i in 0..32 {
        bytes2[i] = 9;
    }

    let compressed1 = CompressedEdwardsY(bytes1);
    println!("{:?}", compressed1.decompress());
    // let compressed2 = CompressedEdwardsY(bytes2);
    // println!("{:?}", compressed2.decompress());
}
