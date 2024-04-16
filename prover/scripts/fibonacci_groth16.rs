//! Tests end-to-end performance of wrapping a recursion proof to Groth16.

#![feature(generic_const_exprs)]

use std::time::Instant;

use itertools::iproduct;
use p3_challenger::CanObserve;
use sp1_core::{
    runtime::Program,
    stark::{Proof, RiscvAir, StarkGenericConfig},
    utils::BabyBearPoseidon2,
};
use sp1_prover::{ReduceProof, SP1ProverImpl};
use sp1_recursion_circuit::{stark::build_wrap_circuit, witness::Witnessable};
use sp1_recursion_compiler::{constraints::groth16_ffi, ir::Witness};
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

    // Setup enviroment variables.
    std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");

    // Initialize prover.
    let prover = SP1ProverImpl::new();

    // Setup sweep.
    let iterations = [480000u32];
    let shard_sizes = [1 << 22];
    let batch_sizes = [2];
    let elf = include_bytes!("../../examples/fibonacci-io/program/elf/riscv32im-succinct-zkvm-elf");

    for (shard_size, iterations, batch_size) in iproduct!(shard_sizes, iterations, batch_sizes) {
        tracing::info!(
            "running: shard_size={}, iterations={}, batch_size={}",
            shard_size,
            iterations,
            batch_size
        );
        std::env::set_var("SHARD_SIZE", shard_size.to_string());

        tracing::info!("proving leaves");
        let stdin = [bincode::serialize::<u32>(&iterations).unwrap()];
        let leaf_proving_start = Instant::now();
        let proof: Proof<BabyBearPoseidon2> = SP1ProverImpl::prove(elf, &stdin);
        let leaf_proving_duration = leaf_proving_start.elapsed().as_secs_f64();
        tracing::info!("leaf_proving_duration={}", leaf_proving_duration);

        tracing::info!("proving inner");
        let sp1_machine = RiscvAir::machine(BabyBearPoseidon2::default());
        let (_, vk) = sp1_machine.setup(&Program::from(elf));
        let mut sp1_challenger = sp1_machine.config().challenger();
        sp1_challenger.observe(vk.commit);
        for shard_proof in proof.shard_proofs.iter() {
            sp1_challenger.observe(shard_proof.commitment.main_commit);
            sp1_challenger.observe_slice(&shard_proof.public_values.to_vec());
        }

        let recursion_proving_start = Instant::now();
        let inner_proof = prover.reduce_tree(&vk, sp1_challenger.clone(), proof, batch_size);
        let recursion_proving_duration = recursion_proving_start.elapsed().as_secs_f64();
        tracing::info!("recursion_proving_duration={}", recursion_proving_duration);

        tracing::info!("proving final bn254");
        let bn254_wrap_start = Instant::now();
        let bn254_proof =
            prover.bn254_reduce(&vk, sp1_challenger, ReduceProof::Recursive(inner_proof));
        let bn254_wrap_proving_duration = bn254_wrap_start.elapsed().as_secs_f64();
        tracing::info!("bn254_wrap_start_duration={}", bn254_wrap_proving_duration);

        tracing::info!("proving groth16");
        let mut witness = Witness::default();
        bn254_proof.write(&mut witness);
        let constraints = build_wrap_circuit(&prover.reduce_vk_outer, bn254_proof);

        tracing::info_span!("generating groth16 proof")
            .in_scope(|| groth16_ffi::prove(constraints, witness));
    }
}
