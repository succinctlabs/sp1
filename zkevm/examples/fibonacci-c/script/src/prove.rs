//! Generate + verify a core proof for fibonacci-c.

use sp1_sdk::{utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("FIBONACCI_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);
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
    let result = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    info!(n = N, fib_mod_7919 = result, "generated core proof");

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    info!("proof verified");
}
