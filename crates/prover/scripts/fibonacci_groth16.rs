//! Tests end-to-end performance of wrapping a recursion proof to PLONK.

use std::time::Instant;

use itertools::iproduct;
use sp1_core_machine::{
    io::SP1Stdin,
    utils::{SP1ProverOpts, SP1ProverOpts},
};
use sp1_prover::SP1Prover;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{fmt::format::FmtSpan, util::SubscriberInitExt};

fn main() {
    // Setup tracer.
    let default_filter = "off";
    let log_appender = tracing_appender::rolling::never("scripts/results", "fibonacci_groth16.log");
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_filter))
        .add_directive("p3_keccak_air=off".parse().unwrap())
        .add_directive("p3_fri=off".parse().unwrap())
        .add_directive("p3_challenger=off".parse().unwrap())
        .add_directive("p3_dft=off".parse().unwrap())
        .add_directive("sp1_core=off".parse().unwrap());
    tracing_subscriber::fmt::Subscriber::builder()
        .with_ansi(false)
        .with_file(false)
        .with_target(false)
        .with_thread_names(false)
        .with_env_filter(env_filter)
        .with_span_events(FmtSpan::CLOSE)
        .with_writer(log_appender)
        .finish()
        .init();

    // Setup environment variables.
    std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");

    // Initialize prover.
    let prover = SP1Prover::new();

    // Setup sweep.
    let iterations = [480000u32];
    let shard_sizes = [1 << 22];
    let batch_sizes = [2];
    let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
    let (pk, vk) = prover.setup(elf);

    for (shard_size, iterations, batch_size) in iproduct!(shard_sizes, iterations, batch_sizes) {
        tracing::info!(
            "running: shard_size={}, iterations={}, batch_size={}",
            shard_size,
            iterations,
            batch_size
        );
        std::env::set_var("SHARD_SIZE", shard_size.to_string());

        tracing::info!("proving leaves");
        let stdin = SP1Stdin {
            buffer: vec![bincode::serialize::<u32>(&iterations).unwrap()],
            ptr: 0,
            proofs: vec![],
        };
        let leaf_proving_start = Instant::now();
        let proof = prover
            .prove_core(&pk, &stdin, SP1ProverOpts::default(), SP1Context::default())
            .unwrap();
        let leaf_proving_duration = leaf_proving_start.elapsed().as_secs_f64();
        tracing::info!("leaf_proving_duration={}", leaf_proving_duration);

        tracing::info!("proving inner");
        let recursion_proving_start = Instant::now();
        let _ = prover.compress(&vk, proof, vec![]);
        let recursion_proving_duration = recursion_proving_start.elapsed().as_secs_f64();
        tracing::info!("recursion_proving_duration={}", recursion_proving_duration);
    }
}
