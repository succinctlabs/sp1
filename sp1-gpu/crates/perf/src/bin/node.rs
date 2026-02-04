use std::time::Duration;

use clap::Parser;
use sp1_core_executor::SP1Context;
use sp1_gpu_perf::{get_program_and_input, Measurement};
use sp1_gpu_prover::cuda_worker_builder;
use sp1_prover::worker::{SP1LocalNodeBuilder, SP1Proof};
use sp1_prover_types::network_base_types::ProofMode;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "local-fibonacci")]
    pub program: String,
    #[arg(long, default_value = "")]
    pub param: String,
    #[arg(long, default_value = "false")]
    pub telemetry: bool,
    #[arg(long, default_value = "core")]
    pub mode: String,
    #[arg(long, short, default_value = "1")]
    pub num_iterations: usize,
}

fn proof_mode_from_string(s: &str) -> ProofMode {
    match s {
        "core" => ProofMode::Core,
        "compressed" => ProofMode::Compressed,
        "groth16" => ProofMode::Groth16,
        "plonk" => ProofMode::Plonk,
        _ => panic!("invalid proof mode provided: {s}"),
    }
}

#[tokio::main]
#[allow(clippy::field_reassign_with_default)]
#[allow(clippy::print_stdout)]
async fn main() {
    let args = Args::parse();

    // Load the environment variables.
    dotenv::dotenv().ok();

    // Initialize the tracer.
    #[cfg(not(feature = "tokio-blocked"))]
    if args.telemetry {
        use opentelemetry::KeyValue;
        use opentelemetry_sdk::Resource;
        use sp1_gpu_perf::telemetry;

        let resource = Resource::new(vec![KeyValue::new("service.name", "sp1-gpu-node")]);
        telemetry::init(resource);
    } else {
        sp1_gpu_tracing::init_tracer();
    }
    #[cfg(feature = "tokio-blocked")]
    {
        use tokio_blocked::TokioBlockedLayer;
        use tracing_subscriber::{prelude::*, EnvFilter};

        let fmt = tracing_subscriber::fmt::layer().with_filter(EnvFilter::from_default_env());

        let duration = std::env::var("TOKIO_BLOCKED_WARN_DURATION_MICROS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(1000);
        let blocked = TokioBlockedLayer::new()
            .with_warn_busy_single_poll(Some(Duration::from_micros(duration)));

        tracing_subscriber::registry().with(fmt).with(blocked).init();
    }

    // Get the program and input.
    let (elf, stdin) = get_program_and_input(args.program.clone(), args.param);

    // Initialize the AirProver and permits
    let measurements = sp1_gpu_cudart::spawn(move |t| async move {
        #[cfg(feature = "experimental")]
        let worker_builder = cuda_worker_builder(t.clone()).await.without_vk_verification();
        #[cfg(not(feature = "experimental"))]
        let worker_builder = cuda_worker_builder(t.clone()).await;
        let client =
            SP1LocalNodeBuilder::from_worker_client_builder(worker_builder).build().await.unwrap();

        let time = tokio::time::Instant::now();
        let context = SP1Context::default();
        tracing::info!("executing the program");
        let (_, _, report) = client.execute(&elf, stdin.clone(), context.clone()).await.unwrap();
        let execute_time = time.elapsed();
        let cycles = report.total_instruction_count() as usize;
        tracing::info!("execute time: {:?}", execute_time);

        let time = tokio::time::Instant::now();
        let vk = client.setup(&elf).await.unwrap();
        let setup_time = time.elapsed();
        tracing::info!("setup time: {:?}", setup_time);

        // Run the prover for a number of iterations.
        let mut measurements = Vec::with_capacity(args.num_iterations);
        for _ in 0..args.num_iterations {
            let mode = proof_mode_from_string(&args.mode);
            let stdin = stdin.clone();
            let context = context.clone();
            let time = tokio::time::Instant::now();
            tracing::info!("proving with mode: {mode:?}");
            let proof = client.prove_with_mode(&elf, stdin, context, mode).await.unwrap();
            let proof_time = time.elapsed();
            tracing::info!("proof time: {:?}", proof_time);

            let num_shards = if let SP1Proof::Core(ref shard_proofs) = &proof.proof {
                shard_proofs.len()
            } else {
                0
            };

            // Verify the proof
            tokio::task::spawn_blocking({
                let client = client.clone();
                let vk = vk.clone();
                move || client.verify(&vk, &proof.proof)
            })
            .await
            .unwrap()
            .unwrap();

            let (core_time, compress_time, shrink_time, wrap_time) = match mode {
                ProofMode::Core => (Some(proof_time), None, Duration::ZERO, Duration::ZERO),
                ProofMode::Compressed => (None, Some(proof_time), Duration::ZERO, Duration::ZERO),
                ProofMode::Groth16 => (None, None, Duration::ZERO, proof_time),
                ProofMode::Plonk => (None, None, Duration::ZERO, proof_time),
                _ => panic!("invalid proof mode: {mode:?}"),
            };
            let measurement = Measurement {
                name: args.program.clone(),
                cycles,
                num_shards,
                core_time,
                compress_time,
                shrink_time,
                wrap_time,
            };
            println!("{measurement}");
            measurements.push(measurement);
        }
        measurements
    })
    .await
    .unwrap();

    if args.telemetry {
        tokio::task::spawn_blocking(opentelemetry::global::shutdown_tracer_provider).await.unwrap();
    }

    println!("All {} measurements done", measurements.len());
}
