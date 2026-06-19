//! Generate + verify a core proof for ecrecover-c.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sp1_sdk::{utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("ECRECOVER_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let sk = SigningKey::random(&mut OsRng);
    let vk = sk.verifying_key();
    let encoded = vk.to_encoded_point(false);
    let mut xy = [0u8; 64];
    xy.copy_from_slice(&encoded.as_bytes()[1..]);

    let msg = b"the quick brown fox jumps over the lazy dog";
    let msg_hash: [u8; 32] = Sha256::digest(msg).into();
    let signature: Signature = sk.sign_prehash(&msg_hash).unwrap();
    let mut recid_byte = 0u8;
    for v in 0u8..4 {
        if let Ok(rid) = RecoveryId::try_from(v) {
            if let Ok(rec) = VerifyingKey::recover_from_prehash(&msg_hash, &signature, rid) {
                if &rec == vk {
                    recid_byte = v;
                    break;
                }
            }
        }
    }

    let mut input = Vec::with_capacity(32 + 64 + 1);
    input.extend_from_slice(&msg_hash);
    input.extend_from_slice(&signature.to_bytes());
    input.push(recid_byte);

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    info!("generated core proof");

    assert_eq!(proof.public_values.as_slice(), xy);
    info!("guest recovered the correct pubkey");

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    info!("proof verified");
}
