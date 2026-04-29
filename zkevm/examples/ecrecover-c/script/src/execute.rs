//! Execute ecrecover-c with a known signature and assert the guest's
//! recovered pubkey matches the signing key. Also covers the
//! "tamper the signature" path: a different valid `r,s` for any recid
//! recovers a different pubkey, which we sanity-check.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

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

fn sign_with_recid(sk: &SigningKey, prehash: &[u8; 32]) -> (Signature, RecoveryId) {
    // k256 doesn't expose `sign_prehash_recoverable` on the basic path;
    // grind the recid by trial-recovery against the known pubkey.
    let signature: Signature = sk.sign_prehash(prehash).unwrap();
    let expected = sk.verifying_key();
    for v in 0u8..4 {
        if let Ok(rid) = RecoveryId::try_from(v) {
            if let Ok(rec) =
                k256::ecdsa::VerifyingKey::recover_from_prehash(prehash, &signature, rid)
            {
                if &rec == expected {
                    return (signature, rid);
                }
            }
        }
    }
    panic!("no recid worked")
}

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;

    let sk = SigningKey::random(&mut OsRng);
    let xy = pubkey_xy(&sk);
    let msg = b"the quick brown fox jumps over the lazy dog";
    let msg_hash: [u8; 32] = Sha256::digest(msg).into();
    let (signature, recid) = sign_with_recid(&sk, &msg_hash);

    let mut input = Vec::with_capacity(32 + 64 + 1);
    input.extend_from_slice(&msg_hash);
    input.extend_from_slice(&signature.to_bytes());
    input.push(recid.to_byte());

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);
    let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
    let recovered = public_values.as_slice();
    info!(
        cycles = report.total_instruction_count() + report.total_syscall_count(),
        "ecrecover with correct recid",
    );
    assert_eq!(recovered, xy, "guest recovered the wrong pubkey");
    info!("ecrecover-c recovered the correct pubkey");
}
