use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("ssz-withdrawals-program");

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let stdin = SP1Stdin::default();

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    client.verify(&proof, &pk.verifying_key(), None).unwrap();
}
