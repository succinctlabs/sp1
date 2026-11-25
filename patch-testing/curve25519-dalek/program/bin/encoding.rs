#![no_main]
sp1_zkvm::entrypoint!(main);

use curve25519_dalek::edwards::CompressedEdwardsY;

fn main() {
    let inputs: Vec<[u8; 32]> = sp1_zkvm::io::read();
    for bytes in inputs {
        let point = CompressedEdwardsY(bytes).decompress();
        sp1_zkvm::io::commit(&point.map(|point| point.compress().to_bytes()));
    }
}
