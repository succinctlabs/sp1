use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("fibonacci-program");

#[tokio::main]
async fn main() {
    // Setup a tracer for logging.
    sp1_sdk::utils::setup_logger();

    let n = 500u32;
    let mut stdin = SP1Stdin::default();
    stdin.write(&n);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();

    // Verify the proof
    client.verify(&proof, &pk.verifying_key(), None).unwrap();
}
