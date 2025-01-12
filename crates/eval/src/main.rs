use anyhow::Result;
use sp1_eval::evaluate_performance;
use sp1_prover::components::CpuProverComponents;
use sp1_stark::SP1ProverOpts;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = SP1ProverOpts::default();
    evaluate_performance::<CpuProverComponents>(opts).await
}
