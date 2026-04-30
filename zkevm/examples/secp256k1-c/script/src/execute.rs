//! Execute secp256k1-c against:
//!
//! 1. A fresh keypair / SHA-256 prehash signed with `k256` — sanity check
//!    that valid signatures verify and tampered ones don't (`smoke`).
//! 2. The Wycheproof ECDSA secp256k1 P1363 SHA-256 corpus (250 cases
//!    covering signature malleability, modular-inverse traps, integer
//!    overflows, modified r/s, edge-case public keys, etc.). Each case
//!    that fits our fixed-width 64-byte sig / 65-byte SEC1 pubkey API
//!    is compared three ways: guest verdict, unpatched-`k256` host
//!    verdict, and the Wycheproof-declared verdict.
//!
//! The hard assertion is **guest == host k256**: a divergence there
//! indicates the SP1-patched `k256` accepts/rejects something the
//! unpatched library doesn't, which is a patch correctness regression.
//! Disagreements between *both* k256s and Wycheproof are surfaced as
//! informational logs — those reflect k256's design choices (it
//! enforces low-s by default, rejects some "special case hash" inputs,
//! etc.).

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;
use zkevm_fixtures::wycheproof_ecdsa;

const ELF_BYTES: &[u8] = include_bytes!(env!("SECP256K1_C_ELF"));
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

async fn run_case(
    client: &impl Prover,
    msg_hash: &[u8; 32],
    sig: &[u8; 64],
    xy: &[u8; 64],
) -> u8 {
    let mut input = Vec::with_capacity(32 + 64 + 64);
    input.extend_from_slice(msg_hash);
    input.extend_from_slice(sig);
    input.extend_from_slice(xy);
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);
    let (public_values, _) = client.execute(ELF, stdin).await.unwrap();
    public_values.as_slice().first().copied().unwrap_or(0)
}

fn host_k256_verify(prehash: &[u8; 32], sig: &[u8; 64], xy: &[u8; 64]) -> bool {
    let signature = match Signature::from_slice(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(xy);
    let vk = match VerifyingKey::from_sec1_bytes(&sec1) {
        Ok(v) => v,
        Err(_) => return false,
    };
    vk.verify_prehash(prehash, &signature).is_ok()
}

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;

    // ---- smoke: round-trip a freshly-generated key ----
    {
        let sk = SigningKey::random(&mut OsRng);
        let xy = pubkey_xy(&sk);
        let msg = b"the quick brown fox jumps over the lazy dog";
        let msg_hash: [u8; 32] = Sha256::digest(msg).into();
        let signature: Signature = sk.sign_prehash(&msg_hash).unwrap();
        assert_eq!(run_case(&client, &msg_hash, &signature.to_bytes().into(), &xy).await, 1);

        let mut tampered = signature.to_bytes();
        tampered[0] ^= 0x01;
        assert_eq!(run_case(&client, &msg_hash, &tampered.into(), &xy).await, 0);
        info!("smoke test passed: valid sig accepted, tampered sig rejected");
    }

    // ---- wycheproof differential ----
    let mut ran = 0usize;
    let mut k256_vs_wycheproof_disagree = 0usize;
    let mut guest_vs_k256_divergences: Vec<(u32, String, bool, u8)> = Vec::new();

    for v in wycheproof_ecdsa::vectors() {
        let host_k256 = host_k256_verify(&v.msg_prehash, &v.sig, &v.pubkey_xy);
        let guest = run_case(&client, &v.msg_prehash, &v.sig, &v.pubkey_xy).await;

        if host_k256 != v.expected_valid {
            k256_vs_wycheproof_disagree += 1;
        }

        let host_byte: u8 = if host_k256 { 1 } else { 0 };
        if guest != host_byte {
            guest_vs_k256_divergences.push((v.tc_id, v.comment.clone(), host_k256, guest));
        }

        ran += 1;
        if ran % 50 == 0 {
            info!(
                ran,
                guest_vs_k256_divergences = guest_vs_k256_divergences.len(),
                k256_vs_wycheproof_disagree,
                "wycheproof progress",
            );
        }
    }

    info!(
        ran,
        k256_vs_wycheproof_disagree,
        guest_vs_k256_divergences = guest_vs_k256_divergences.len(),
        "wycheproof secp256k1 differential complete",
    );

    if !guest_vs_k256_divergences.is_empty() {
        for (tc, comment, host_k256, guest) in &guest_vs_k256_divergences {
            tracing::error!(
                tc,
                host_k256_valid = host_k256,
                guest_verified = guest,
                comment,
                "patched-k256 (guest) disagrees with unpatched-k256 (host)",
            );
        }
        panic!(
            "{} patch divergence(s) between patched-k256 (guest) and unpatched-k256 (host)",
            guest_vs_k256_divergences.len()
        );
    }
}
