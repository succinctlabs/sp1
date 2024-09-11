#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_lib::verify::verify_plonk_proof;
use substrate_bn::Fr;

pub fn main() {
    let proof = sp1_zkvm::io::read_vec()[8..].to_vec();
    let vk = sp1_zkvm::io::read_vec()[8..].to_vec();
    let vkey_hash = &sp1_zkvm::io::read_vec()[8..];
    let committed_values_digest_bytes = sp1_zkvm::io::read_vec()[8..].to_vec();

    verify_plonk_proof(&proof, &vk, &vkey_hash, &committed_values_digest_bytes);
}
