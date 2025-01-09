#![no_main]
sp1_zkvm::entrypoint!(main);

use curve25519_dalek_ng::edwards::CompressedEdwardsY;
use curve25519_dalek_ng::edwards::EdwardsPoint;

/// Emits ED_DECOMPRESS syscall.
fn main() {
    let mut bytes1: [u8; 32] = [0; 32];
    for i in 0..32 {
        bytes1[i] = 3;
    }
    let compressed1 = CompressedEdwardsY(bytes1);
    let point1 = compressed1.decompress().unwrap();

    let scalar1 = curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order([0u8; 32]);
    let scalar2 = curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order([0u8; 32]);
    let result = EdwardsPoint::vartime_double_scalar_mul_basepoint(&scalar1, &point1, &scalar2);
    println!("{:?}", result.compress());
}
