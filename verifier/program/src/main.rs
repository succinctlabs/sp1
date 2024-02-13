//! A curta proof verifier program to be proven inside the zkVM.

use curta_core::utils::BabyBearBlake3;
use curta_core::{CurtaProofWithIO, CurtaVerifier};

#![no_main]
succinct_zkvm::entrypoint!(main);

pub fn main() {
    
    let proof_str = include_str!("../../examples/ed25519/src/proof-with-pis.json");
    let new_proof: CurtaProofWithIO<BabyBearBlake3> =
        serde_json::from_str(proof_str).expect("loading proof failed");
    CurtaVerifier::verify(ED25519_ELF, &new_proof).expect("verification failed");

    // Verify proof.
    CurtaVerifier::verify(ED25519_ELF, &proof).expect("verification failed");
}
