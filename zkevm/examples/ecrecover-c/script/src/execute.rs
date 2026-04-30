//! Execute ecrecover-c against:
//!
//! 1. A round-trip smoke test with a freshly-generated signing key.
//! 2. Every Wycheproof ECDSA secp256k1 case that passes unpatched-k256
//!    verify, with the recovery id ground out on the host. The guest's
//!    recovered pubkey must equal the expected pubkey for those cases.
//!    Wycheproof "invalid" cases are skipped — recovery from a sig the
//!    underlying ECDSA library would reject doesn't have a well-defined
//!    expectation, and our `recover_from_prehash` returns `Err` for
//!    them, surfacing as `ZKVM_EFAIL` (early exit, no public output).

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;
use zkevm_fixtures::wycheproof_ecdsa;

const ELF_BYTES: &[u8] = include_bytes!(env!("ECRECOVER_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

fn pubkey_xy(sk: &SigningKey) -> [u8; 64] {
    let vk = sk.verifying_key();
    let encoded = vk.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    assert_eq!(bytes[0], 0x04);
    let mut xy = [0u8; 64];
    xy.copy_from_slice(&bytes[1..]);
    xy
}

fn host_verify(prehash: &[u8; 32], sig: &Signature, xy: &[u8; 64]) -> bool {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(xy);
    let vk = match VerifyingKey::from_sec1_bytes(&sec1) {
        Ok(v) => v,
        Err(_) => return false,
    };
    vk.verify_prehash(prehash, sig).is_ok()
}

/// Try recids 0..=3 and return the one that recovers a key matching
/// `expected_xy`, if any.
fn grind_recid(prehash: &[u8; 32], sig: &Signature, expected_xy: &[u8; 64]) -> Option<u8> {
    for v in 0u8..4 {
        let rid = RecoveryId::try_from(v).ok()?;
        if let Ok(rec) = VerifyingKey::recover_from_prehash(prehash, sig, rid) {
            let encoded = rec.to_encoded_point(false);
            let bytes = encoded.as_bytes();
            if bytes.len() == 65 && bytes[0] == 0x04 && &bytes[1..] == expected_xy {
                return Some(v);
            }
        }
    }
    None
}

async fn run_case(
    client: &impl Prover,
    msg_hash: &[u8; 32],
    sig: &[u8; 64],
    recid: u8,
) -> Vec<u8> {
    let mut input = Vec::with_capacity(32 + 64 + 1);
    input.extend_from_slice(msg_hash);
    input.extend_from_slice(sig);
    input.push(recid);
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);
    let (public_values, _) = client.execute(ELF, stdin).await.unwrap();
    public_values.as_slice().to_vec()
}

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;

    // ---- smoke ----
    {
        let sk = SigningKey::random(&mut OsRng);
        let xy = pubkey_xy(&sk);
        let msg = b"the quick brown fox jumps over the lazy dog";
        let msg_hash: [u8; 32] = Sha256::digest(msg).into();
        let signature: Signature = sk.sign_prehash(&msg_hash).unwrap();
        let recid = grind_recid(&msg_hash, &signature, &xy).expect("smoke: recid not found");
        let recovered = run_case(&client, &msg_hash, &signature.to_bytes().into(), recid).await;
        assert_eq!(recovered.as_slice(), &xy[..]);
        info!("smoke test passed: ecrecover round-trip matches the signing key");
    }

    // ---- wycheproof: only cases where host k256 verify accepts ----
    let mut tested = 0usize;
    let mut skipped_invalid = 0usize;
    let mut skipped_no_recid = 0usize;
    let mut mismatches: Vec<(u32, String)> = Vec::new();

    for v in wycheproof_ecdsa::vectors() {
        let signature = match Signature::from_slice(&v.sig) {
            Ok(s) => s,
            Err(_) => {
                skipped_invalid += 1;
                continue;
            }
        };
        if !host_verify(&v.msg_prehash, &signature, &v.pubkey_xy) {
            skipped_invalid += 1;
            continue;
        }
        let recid = match grind_recid(&v.msg_prehash, &signature, &v.pubkey_xy) {
            Some(r) => r,
            None => {
                skipped_no_recid += 1;
                continue;
            }
        };

        let recovered = run_case(&client, &v.msg_prehash, &v.sig, recid).await;
        if recovered.as_slice() != v.pubkey_xy.as_slice() {
            mismatches.push((v.tc_id, v.comment.clone()));
        }
        tested += 1;

        if tested % 25 == 0 {
            info!(tested, mismatches = mismatches.len(), "wycheproof ecrecover progress");
        }
    }

    info!(
        tested,
        skipped_invalid,
        skipped_no_recid,
        mismatches = mismatches.len(),
        "wycheproof ecrecover differential complete",
    );

    if !mismatches.is_empty() {
        for (tc, comment) in &mismatches {
            tracing::error!(tc, comment, "ecrecover mismatch");
        }
        panic!("{} ecrecover case(s) returned the wrong pubkey", mismatches.len());
    }
}
