use anyhow::Result;
use sp1_eval::evaluate_performance;
use sp1_prover::components::DefaultProverComponents;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    evaluate_performance::<DefaultProverComponents>().await
}
