use curve25519_dalek_ng::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use ed25519_consensus::{batch, Signature, SigningKey, VerificationKey, VerificationKeyBytes};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha512};

pub type Case = ([u8; 32], Vec<u8>, Vec<u8>);

pub fn encodings() -> Vec<[u8; 32]> {
    let mut encodings = Vec::new();
    for noncanonical in [false, true] {
        for offset in 0..19u8 {
            for sign in [0u8, 0x80] {
                let mut bytes = if noncanonical { [255; 32] } else { [0; 32] };
                bytes[0] = if noncanonical { 237 + offset } else { offset };
                bytes[31] = if noncanonical { 0x7f | sign } else { sign };
                encodings.push(bytes);
            }
        }
    }
    encodings
}

pub fn verify(case: &Case) -> bool {
    let (key, signature, message) = case;
    VerificationKey::try_from(*key)
        .and_then(|key| key.verify(&Signature::try_from(signature.as_slice())?, message))
        .is_ok()
}

pub fn verify_batch(cases: &[Case]) -> bool {
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

pub fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut identity_signature = [0u8; 64];
    identity_signature[..32].copy_from_slice(&identity);

    // These encodings represent identity or order-four points. ZIP-215
    // deliberately removes their torsion in its cofactored equation.
    for offset in [0u8, 1] {
        for sign in [0u8, 0x80] {
            let mut point = [255; 32];
            point[0] = 237 + offset;
            point[31] = 0x7f | sign;
            cases.push((point, identity_signature.to_vec(), b"noncanonical key".to_vec()));
            let mut signature = identity_signature;
            signature[..32].copy_from_slice(&point);
            cases.push((identity, signature.to_vec(), b"noncanonical R".to_vec()));
        }
    }

    // Use a nonidentity key so the challenge affects verification. Changing
    // R's encoding without updating s must reject, even though R is unchanged.
    let secret = Scalar::from(7u64);
    let key = (secret * ED25519_BASEPOINT_POINT).compress().to_bytes();
    for sign in [0u8, 0x80] {
        for message in [b"original bytes".as_slice(), b"second message".as_slice()] {
            let mut r = [255; 32];
            r[0] = 238;
            r[31] = 0x7f | sign;
            let mut hash = Sha512::new();
            hash.update(&r);
            hash.update(&key);
            hash.update(message);
            let mut wide = [0u8; 64];
            wide.copy_from_slice(&hash.finalize());
            let s = Scalar::from_bytes_mod_order_wide(&wide) * secret;
            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(&r);
            signature[32..].copy_from_slice(&s.to_bytes());
            let valid = (key, signature.to_vec(), message.to_vec());
            assert!(verify(&valid));
            cases.push(valid);
            let changed_message = (key, signature.to_vec(), b"changed message".to_vec());
            assert!(!verify(&changed_message));
            cases.push(changed_message);
            signature[..32].copy_from_slice(&identity);
            let changed_encoding = (key, signature.to_vec(), message.to_vec());
            assert!(!verify(&changed_encoding));
            cases.push(changed_encoding);
        }
    }
    for seed in [1u8, 7, 255] {
        let signing = SigningKey::from([seed; 32]);
        let key = VerificationKey::from(&signing).to_bytes();
        let signature = signing.sign(b"canonical control").to_bytes().to_vec();
        cases.push((key, signature.clone(), b"canonical control".to_vec()));
        cases.push((key, signature, b"wrong message".to_vec()));
    }
    cases
}

pub fn verify_patched(case: &Case) -> bool {
    use ed25519_consensus_patched::{Signature, VerificationKey};
    let (key, signature, message) = case;
    VerificationKey::try_from(*key)
        .and_then(|key| key.verify(&Signature::try_from(signature.as_slice())?, message))
        .is_ok()
}

pub fn verify_batch_patched(cases: &[Case]) -> bool {
    use ed25519_consensus_patched::{batch, Signature, VerificationKeyBytes};
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
