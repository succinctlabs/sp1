use std::time::Instant;

use sp1_sdk::{Prover, ProverClient};
use test_artifacts::FIBONACCI_ELF;

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let t = Instant::now();
    let client = ProverClient::builder().cpu().build().await;
    let init_time = t.elapsed();
    tracing::info!("prover init time: {init_time:?}");

    let t = Instant::now();
    let _pk = client.setup(FIBONACCI_ELF).await.unwrap();
    let setup_time = t.elapsed();
    tracing::info!("setup time: {setup_time:?}");
}
