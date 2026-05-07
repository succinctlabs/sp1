//! Generate + verify a core proof for invalid-hint-c. The guest is run
//! with flag=1 so `zkvm_invalid_hint()` halts with exit code 3; the
//! verifier then accepts the proof iff it's checked against
//! `StatusCode::INVALID_HINT`.

use sp1_sdk::{utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin, StatusCode};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("INVALID_HINT_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&[1u8]);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();

    info!("generated core proof for invalid-hint-c invalid_hint path (flag=1)");

    client
        .verify(&proof, pk.verifying_key(), StatusCode::new(3))
        .expect("verification with exit code 3 failed");
    info!("proof verified with expected exit code 3 (StatusCode::INVALID_HINT)");
}
