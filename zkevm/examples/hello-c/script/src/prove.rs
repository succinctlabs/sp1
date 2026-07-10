//! Generate a core proof for the `hello-c` C guest, verify it, and
//! check the public output matches the input.

use sp1_sdk::{utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("HELLO_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let input: &[u8] = b"hello from the host (C)";
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(input);

    let client = ProverClient::from_env().await;

    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    info!("generated core proof");

    let output = proof.public_values.as_slice();
    info!(output = %core::str::from_utf8(output).unwrap_or("<non-utf8>"), "public output");
    assert_eq!(output, input);

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    info!("proof verified");
}
