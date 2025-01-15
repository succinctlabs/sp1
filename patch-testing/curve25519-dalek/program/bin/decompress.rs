#![no_main]
sp1_zkvm::entrypoint!(main);

use curve25519_dalek::edwards::CompressedEdwardsY;

/// Emits ED_DECOMPRESS syscall.
fn main() {
    let times: usize = sp1_zkvm::io::read();

    for i in 0..times {
        println!("Decompressing the {i}th point");
        let compressed: CompressedEdwardsY = sp1_zkvm::io::read();
        let decompressed = compressed.decompress();

        sp1_zkvm::io::commit(&decompressed);
    }
}
