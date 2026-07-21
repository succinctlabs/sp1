//! Generate + verify a core proof for ripemd-c.

use ripemd::{Digest, Ripemd160};
use sp1_sdk::{utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("RIPEMD_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let input: &[u8] = b"The quick brown fox jumps over the lazy dog";
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(input);

    let mut hasher = Ripemd160::new();
    hasher.update(input);
    let digest = hasher.finalize();
    let mut expected = [0u8; 32];
    expected[..20].copy_from_slice(&digest);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    info!("generated core proof");

    let guest_digest = proof.public_values.as_slice();
    assert_eq!(guest_digest, &expected[..]);
    info!("digest matches host-computed RIPEMD-160");

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    info!("proof verified");
}
