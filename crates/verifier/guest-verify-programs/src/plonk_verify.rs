#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_verifier::PlonkVerifier;

fn main() {
    // Read the proof, public values, and vkey hash from the input stream.
    let proof = sp1_zkvm::io::read_vec();
    let sp1_public_values = sp1_zkvm::io::read_vec();
    let sp1_vkey_hash: String = sp1_zkvm::io::read();

    // Verify the groth16 proof.
    let plonk_vk = *sp1_verifier::PLONK_VK_BYTES;
    let result =
        PlonkVerifier::verify(&proof, &sp1_public_values, &sp1_vkey_hash, plonk_vk).unwrap();
}
