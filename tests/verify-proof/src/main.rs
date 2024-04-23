#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};
use sp1_zkvm::precompiles::verify::verify_sp1_proof;

fn words_to_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let word_bytes = words[i].to_le_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    bytes
}

pub fn main() {
    let vkey = sp1_zkvm::io::read::<[u32; 8]>();
    println!("Read vkey: {:?}", hex::encode(words_to_bytes(&vkey)));
    let inputs = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    inputs.iter().for_each(|input| {
        let pv_digest = sp1_zkvm::io::read::<[u32; 8]>();
        verify_sp1_proof(&vkey, &pv_digest);

        println!(
            "Verified proof for digest: {:?}",
            hex::encode(words_to_bytes(&pv_digest))
        );
        // Ensure sha2(input) matches hash
        let hash = Sha256::digest(input);
        let pv_digest_bytes: [u8; 32] = pv_digest
            .iter()
            .flat_map(|x| x.to_le_bytes().to_vec())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert_eq!(hash, pv_digest_bytes.into());
        println!("Verified input: {:?}", input);
    });
}
