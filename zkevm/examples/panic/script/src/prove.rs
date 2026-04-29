//! Generate + verify a core proof for the panic guest. The guest is run with
//! flag=1 so it panics; verification then succeeds only when passed the
//! matching non-zero exit code.

use sp1_sdk::{
    include_elf, utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin, StatusCode,
};
use tracing::info;

const ELF: Elf = include_elf!("panic");

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&[1u8]);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();

    info!("generated core proof for panic path (flag=1)");

    client
        .verify(&proof, pk.verifying_key(), StatusCode::new(1))
        .expect("verification with exit code 1 failed");
    info!("proof verified with expected exit code 1");
}
