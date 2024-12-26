#![no_main]
sp1_zkvm::entrypoint!(main);

use curve25519_dalek_ng::edwards::CompressedEdwardsY;

/// Emits ED_DECOMPRESS syscall.
fn main() {
    let mut bytes1: [u8; 32] = [0; 32];
    for i in 0..32 {
        bytes1[i] = 3;
    }
    let mut bytes2: [u8; 32] = [0; 32];
    for i in 0..32 {
        bytes2[i] = 9;
    }

    let compressed1 = CompressedEdwardsY(bytes1);
    let point1 = compressed1.decompress().unwrap();
    let compressed2 = CompressedEdwardsY(bytes2);
    let point2 = compressed2.decompress().unwrap();

    let scalar = curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order([1u8; 32]);
    let point = point1 + point2;
    let result = point * scalar;
    println!("{:?}", result.compress());
}
