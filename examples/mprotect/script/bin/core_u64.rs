use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;


/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("mprotect-program");

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let mut stdin = SP1Stdin::default();
    // Set the flags to true to test the failure cases.
    let execute_prot_should_fail = false;
    let test_prot_none_fail = false;

    stdin.write(&execute_prot_should_fail);
    stdin.write(&test_prot_none_fail);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    client.verify(&proof, &pk.verifying_key(), None).unwrap();
}
