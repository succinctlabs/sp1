//! Generate + verify a core proof for sha256-c.

use sha2::Digest;
use sp1_sdk::{utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("SHA256_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let input: &[u8] = b"The quick brown fox jumps over the lazy dog";
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(input);

    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    let expected: [u8; 32] = hasher.finalize().into();

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    info!("generated core proof");

    let digest = proof.public_values.as_slice();
    assert_eq!(digest, &expected[..]);
    info!("digest matches host-computed sha256");

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    info!("proof verified");
}
