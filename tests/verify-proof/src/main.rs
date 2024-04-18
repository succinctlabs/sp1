#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::precompiles::verify::verify_sp1_proof;

pub fn main() {
    let vkey = sp1_zkvm::io::read::<[u32; 8]>();
    let pv_digest = sp1_zkvm::io::read::<[u32; 8]>();

    verify_sp1_proof(&vkey, &pv_digest);
}
