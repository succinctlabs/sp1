#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_verifier::Groth16Verifier;

fn main() {
    // Read the proof, public values, and vkey hash from the input stream.
    let proof = sp1_zkvm::io::read_vec();
    let sp1_public_values = sp1_zkvm::io::read_vec();
    let sp1_vkey_hash: String = sp1_zkvm::io::read();

    // Verify the plonk proof.
    let groth16_vk = *sp1_verifier::GROTH16_VK_BYTES;
    let result =
        Groth16Verifier::verify(&proof, &sp1_public_values, &sp1_vkey_hash, groth16_vk).unwrap();
}
