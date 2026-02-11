use std::{
    future::Future,
    time::{Duration, Instant},
};

use async_scoped::TokioScope;
use clap::Parser;
use sp1_core_executor::ExecutionError;
use sp1_cuda::CudaClientError;
use sp1_prover::ProverMode;
use sp1_sdk::{
    cpu::CPUProverError,
    network::{signer::NetworkSigner, FulfillmentStrategy, NetworkMode},
    Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin, SP1VerificationError,
};
use thiserror::Error;
use tokio::task::JoinError;

#[derive(Parser, Clone)]
#[command(about = "Evaluate the performance of SP1 on programs.")]
struct Args {
    /// The program to evaluate.
    #[arg(short, long)]
    pub program: String,

    /// The input to the program being evaluated.
    #[arg(short, long)]
    pub stdin: String,

    /// The prover mode to use.
    #[arg(short, long)]
    pub mode: ProverMode,

    /// The number of times to repeat the evaluation concurrently (using tokio tasks).
    #[arg(short, long, default_value = "1")]
    pub concurrent_repeat_count: usize,
}

#[derive(Default, Debug, Clone)]
#[allow(dead_code)]
struct PerfSummary {
    pub cycles: u64,
    pub execution_duration: Duration,
    pub prover_init_duration: Duration,
    pub setup_duration: Duration,
    pub prove_duration: Duration,
    pub verify_duration: Duration,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to join a task: {0}")]
    JoinError(#[from] JoinError),
    #[error("Failed to execute the program: {0}")]
    ExecutionError(#[from] ExecutionError),
    #[error("Failed to setup the prover: {0}")]
    CPUProverError(#[from] CPUProverError),
    #[error("Failed to prove the program: {0}")]
    CudaClientError(#[from] CudaClientError),
    #[error("Failed to verify the proof: {0}")]
    NetworkProverError(anyhow::Error),
    #[error("An unexpected error occurred: {0}")]
    UnexpectedError(#[from] anyhow::Error),
    #[error("Failed to verify the proof: {0}")]
    VerificationError(#[from] SP1VerificationError),
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();
    tracing::info!(
        "Running program {} with stdin {} using {:?} (concurrent_repeat_count: {})",
        args.program,
        args.stdin,
        args.mode,
        args.concurrent_repeat_count
    );
    let elf = &Elf::Dynamic(std::fs::read(args.program).expect("failed to read program").into());
    let stdin = std::fs::read(args.stdin).expect("failed to read stdin");
    let stdin = &bincode::deserialize::<SP1Stdin>(&stdin).expect("failed to deserialize stdin");

    let performance_reports = match args.mode {
        ProverMode::Cpu => {
            let (ref prover, prover_init_duration) =
                time_operation_fut(async || ProverClient::builder().cpu().build().await).await;

            repeat_concurrent(args.concurrent_repeat_count, || async move {
                let (execution_result, execution_duration) =
                    time_operation_fut(async || prover.execute(elf.clone(), stdin.clone()).await)
                        .await;
                let (_, execution_report) = execution_result?;

                let (pk, setup_duration) =
                    time_operation_fut(async || prover.setup(elf.clone()).await).await;
                let pk = pk?;

                let (proof, prove_duration) = time_operation_fut(async || {
                    prover.prove(&pk, stdin.clone()).compressed().await
                })
                .await;
                let proof = proof?;

                let (verify_result, verify_duration) =
                    time_operation(|| prover.verify(&proof, pk.verifying_key(), None));
                let () = verify_result?;

                Ok(PerfSummary {
                    cycles: execution_report.total_instruction_count(),
                    execution_duration,
                    prover_init_duration,
                    setup_duration,
                    prove_duration,
                    verify_duration,
                })
            })
            .await
        }
        ProverMode::Cuda => {
            let (ref prover, prover_init_duration) =
                time_operation_fut(async || ProverClient::builder().cuda().build().await).await;

            repeat_concurrent(args.concurrent_repeat_count, || async move {
                let (execution_result, execution_duration) =
                    time_operation_fut(async || prover.execute(elf.clone(), stdin.clone()).await)
                        .await;
                let (_, execution_report) = execution_result?;

                let (pk, setup_duration) =
                    time_operation_fut(async || prover.setup(elf.clone()).await).await;
                let pk = pk?;

                let (proof, prove_duration) = time_operation_fut(async || {
                    prover.prove(&pk, stdin.clone()).compressed().await
                })
                .await;
                let proof = proof?;

                let (verify_result, verify_duration) =
                    time_operation(|| prover.verify(&proof, pk.verifying_key(), None));
                let () = verify_result?;

                Ok(PerfSummary {
                    cycles: execution_report.total_instruction_count(),
                    execution_duration,
                    prover_init_duration,
                    setup_duration,
                    prove_duration,
                    verify_duration,
                })
            })
            .await
        }
        ProverMode::Network => {
            let private_key = std::env::var("NETWORK_PRIVATE_KEY")
                .expect("NETWORK_PRIVATE_KEY environment variable must be set");
            let auction_timeout = Duration::from_secs(
                std::env::var("AUCTION_TIMEOUT_SECONDS").map_or(60, |s| s.parse().unwrap()),
            );
            let signer = NetworkSigner::local(&private_key).expect("failed to create signer");
            let (ref prover, prover_init_duration) = time_operation_fut(async || {
                ProverClient::builder()
                    .network_for(NetworkMode::Mainnet)
                    .rpc_url("https://rpc.sepolia.succinct.xyz")
                    .signer(signer)
                    .build()
                    .await
            })
            .await;

            repeat_concurrent(args.concurrent_repeat_count, || async move {
                let (execution_result, execution_duration) =
                    time_operation_fut(async || prover.execute(elf.clone(), stdin.clone()).await)
                        .await;
                let (_, execution_report) = execution_result?;

                let (pk, setup_duration) =
                    time_operation_fut(async || prover.setup(elf.clone()).await).await;
                let pk = pk.map_err(Error::NetworkProverError)?;

                let (proof, prove_duration) = time_operation_fut(async || {
                    prover
                        .prove(&pk, stdin.clone())
                        .strategy(FulfillmentStrategy::Auction)
                        .auction_timeout(auction_timeout)
                        .min_auction_period(1)
                        .cycle_limit(100_000_000_000)
                        .gas_limit(10_000_000_000)
                        .max_price_per_pgu(600_000_000)
                        .skip_simulation(true)
                        .compressed()
                        .await
                })
                .await;
                let proof = proof.map_err(Error::NetworkProverError)?;

                let (verify_result, verify_duration) =
                    time_operation(|| prover.verify(&proof, pk.verifying_key(), None));
                let () = verify_result?;

                Ok(PerfSummary {
                    cycles: execution_report.total_instruction_count(),
                    execution_duration,
                    prover_init_duration,
                    setup_duration,
                    prove_duration,
                    verify_duration,
                })
            })
            .await
        }
        ProverMode::Mock => unreachable!(),
    };

    let performance_reports = performance_reports
        .into_iter()
        .map(|result| result?)
        .collect::<Vec<Result<PerfSummary, Error>>>();

    tracing::info!("{performance_reports:#?}");

    for result in performance_reports {
        result.unwrap();
    }
}

pub async fn repeat_concurrent<F: Future<Output: Send + 'static> + Send>(
    count: usize,
    f: impl Fn() -> F,
) -> Vec<Result<F::Output, JoinError>> {
    let ((), outputs) = unsafe {
        // Safety: This is safe as long as we do not `std::mem::forget` the returned future.
        TokioScope::scope_and_collect(|scope| {
            for _ in 0..count {
                scope.spawn(f());
            }
        })
        .await
    };
    outputs
}

pub async fn time_operation_fut<F: Future>(
    f: impl FnOnce() -> F,
) -> (F::Output, std::time::Duration) {
    let start = Instant::now();
    let result = f().await;
    let duration = start.elapsed();
    (result, duration)
}

pub fn time_operation<T>(f: impl FnOnce() -> T) -> (T, std::time::Duration) {
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    (result, duration)
}
