#![no_main]
sp1_zkvm::entrypoint!(main);

use ed25519_consensus::{batch, Signature, VerificationKey, VerificationKeyBytes};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

type Case = ([u8; 32], Vec<u8>, Vec<u8>);

fn verify_batch(cases: &[Case]) -> bool {
    let mut verifier = batch::Verifier::new();
    for (key, signature, message) in cases {
        verifier.queue((
            VerificationKeyBytes::from(*key),
            Signature::try_from(signature.as_slice()).unwrap(),
            message.as_slice(),
        ));
    }
    verifier.verify(ChaCha20Rng::from_seed([42; 32])).is_ok()
}

fn main() {
    let encodings: Vec<[u8; 32]> = sp1_zkvm::io::read();
    let cases: Vec<Case> = sp1_zkvm::io::read();
    let valid: Vec<Case> = sp1_zkvm::io::read();
    let mixed: Vec<Case> = sp1_zkvm::io::read();
    let keys: Vec<_> = encodings
        .into_iter()
        .map(|bytes| VerificationKey::try_from(bytes).ok().map(|key| key.to_bytes()))
        .collect();
    sp1_zkvm::io::commit(&keys);
    let results: Vec<_> = cases
        .iter()
        .map(|case| {
            let (key, signature, message) = case;
            let individual = VerificationKey::try_from(*key)
                .and_then(|key| key.verify(&Signature::try_from(signature.as_slice())?, message))
                .is_ok();
            (individual, verify_batch(std::slice::from_ref(case)))
        })
        .collect();
    sp1_zkvm::io::commit(&results);
    sp1_zkvm::io::commit(&verify_batch(&valid));
    sp1_zkvm::io::commit(&verify_batch(&mixed));
}
