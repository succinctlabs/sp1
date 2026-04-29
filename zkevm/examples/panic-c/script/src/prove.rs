//! Generate + verify a core proof for panic-c. The guest is run with flag=1
//! so it calls abort(); verification then succeeds only when passed the
//! matching non-zero exit code.

use sp1_sdk::{utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin, StatusCode};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("PANIC_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&[1u8]);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();

    info!("generated core proof for panic-c path (flag=1)");

    client
        .verify(&proof, pk.verifying_key(), StatusCode::new(1))
        .expect("verification with exit code 1 failed");
    info!("proof verified with expected exit code 1");
}
