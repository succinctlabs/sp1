//! Generate + verify a core proof for fibonacci(n).

use sp1_sdk::{include_elf, utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tracing::info;

const ELF: Elf = include_elf!("fibonacci");
const N: u32 = 1000;

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&N.to_le_bytes());

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();

    let bytes = proof.public_values.as_slice();
    assert_eq!(bytes.len(), 4);
    let result = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    info!(n = N, fib_mod_7919 = result, "generated core proof");

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    info!("proof verified");
}
