//! Generate + verify a core proof for secp256k1-c on a valid signature.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sp1_sdk::{utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("SECP256K1_C_ELF"));
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

    let mut input = Vec::with_capacity(32 + 64 + 64);
    input.extend_from_slice(&msg_hash);
    input.extend_from_slice(&signature.to_bytes());
    input.extend_from_slice(&xy);

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    info!("generated core proof");

    assert_eq!(proof.public_values.as_slice(), &[1u8]);
    info!("guest reported signature verified");

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    info!("proof verified");
}
