#![no_main]
sp1_zkvm::entrypoint!(main);

use curve25519_dalek_ng::edwards::CompressedEdwardsY;
use curve25519_dalek_ng::scalar::Scalar;

/// Emits ED_DECOMPRESS syscall.
fn main() {
    let times = sp1_zkvm::io::read::<u16>();
    for _ in 0..times {
        let bytes1: [u8; 32] = sp1_zkvm::io::read();
        let bytes2: [u8; 32] = sp1_zkvm::io::read();
        let scalar: [u8; 32] = sp1_zkvm::io::read();

        let compressed1 = CompressedEdwardsY(bytes1);
        let point1 = compressed1.decompress();
        let compressed2 = CompressedEdwardsY(bytes2);
        let point2 = compressed2.decompress();

        if point1.is_some() && point2.is_some() {
            let point = point1.unwrap() + point2.unwrap();
            let scalar = Scalar::from_bytes_mod_order(scalar);
            let result = point * scalar;
            sp1_zkvm::io::commit(result.compress().as_bytes());
        } else {
            sp1_zkvm::io::commit(compressed1.as_bytes());
        }
    }
}
