use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("sha-bench-program");

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let stdin = SP1Stdin::new();
    let client = ProverClient::from_env().await;

    let (_, report) = client.execute(ELF, stdin.clone()).await.unwrap();
    println!("executed program {:?} ", report);

    let pk = client.setup(ELF).await.unwrap();
    let time = std::time::Instant::now();
    let proof = client.prove(&pk, stdin.clone()).compressed().await.unwrap();
    println!("generated proof in {:?}", time.elapsed());

    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    println!("verified proof");
}
