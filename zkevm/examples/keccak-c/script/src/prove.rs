//! Generate + verify a core proof for keccak-c.

use sp1_sdk::{utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tiny_keccak::{Hasher, Keccak};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("KECCAK_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let input: &[u8] = b"The quick brown fox jumps over the lazy dog";
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(input);

    let mut hasher = Keccak::v256();
    hasher.update(input);
    let mut expected = [0u8; 32];
    hasher.finalize(&mut expected);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    info!("generated core proof");

    let digest = proof.public_values.as_slice();
    assert_eq!(digest, &expected[..]);
    info!("digest matches host-computed keccak256");

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    info!("proof verified");
}
