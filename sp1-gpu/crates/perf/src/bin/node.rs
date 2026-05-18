use std::{borrow::Borrow, time::Duration};

use clap::Parser;
use slop_algebra::AbstractField;
use sp1_core_executor::SP1Context;
use sp1_gpu_perf::{get_program_and_input, Measurement};
use sp1_gpu_prover::cuda_worker_builder_with_machine;
use sp1_primitives::{hash_deferred_proof, SP1Field};
use sp1_prover::worker::{SP1LocalNodeBuilder, SP1Proof};
use sp1_prover_types::network_base_types::ProofMode;
use sp1_recursion_executor::RecursionPublicValues;
use sp1_sdk::{HashableKey, RiscvAir, SP1Stdin, SP1VerifyingKey};

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
    // let (elf, stdin) = get_program_and_input(args.program.clone(), args.param);
    println!("Current directory: {}", std::env::current_dir().unwrap().display());
    let elf = std::fs::read("program.elf").unwrap();
    let stdin_raw = std::fs::read("stdin.bin").unwrap();
    let stdin: SP1Stdin = bincode::deserialize(&stdin_raw).unwrap();
    let machine = RiscvAir::machine();

    let proofs = stdin.proofs.clone();

    // Initialize the AirProver and permits
    let measurements = sp1_gpu_cudart::spawn(move |t| async move {
        let base_builder = cuda_worker_builder_with_machine(t.clone(), machine).await;
        #[cfg(feature = "mprotect")]
        let worker_builder = base_builder.without_vk_verification();
        #[cfg(not(feature = "mprotect"))]
        let worker_builder = base_builder;
        let client =
            SP1LocalNodeBuilder::from_worker_client_builder(worker_builder).build().await.unwrap();

        // Diagnostic: what the GUEST will eventually receive at the VERIFY_SP1_PROOF syscall site
        // is whatever `[u32; 8]` value it reads from stdin (typically the first read). Print every
        // candidate `[u32; 8]` blob in stdin.buffer so we can spot the one the guest is using.
        for (i, blob) in stdin.buffer.iter().enumerate() {
            match bincode::deserialize::<[u32; 8]>(blob) {
                Ok(v) => println!("stdin.buffer[{i}] decodes as [u32;8] = {v:?}"),
                Err(_) => println!(
                    "stdin.buffer[{i}] is not a [u32;8] ({} bytes, first ≤16: {:?})",
                    blob.len(),
                    &blob[..blob.len().min(16)]
                ),
            }
        }

        // Compute `digest_A` — the value the DEFERRED recursion verifier will accumulate into
        // `reconstruct_deferred_digest` starting from the all-zero chain. Mirrors
        // `hash_deferred_proofs` in `crates/prover/src/worker/controller/deferred.rs` and the
        // circuit logic in `SP1DeferredVerifier::verify` (deferred.rs:196-208).
        let mut digest_a = [SP1Field::zero(); 8];
        for (i, (recursion_proof, vk)) in proofs.iter().enumerate() {
            let vk_outer = SP1VerifyingKey { vk: vk.clone() };

            // Use hash_u32 so the format matches the `[u32; 8]` we observe in the child's ecall
            // log (the guest passes `&[u32; 8]` to verify_sp1_proof, which the ecall handler
            // reinterprets from 4 u64 words; both end up canonical u32).
            let vk_digest_u32 = vk_outer.hash_u32();
            let vk_digest_kb = vk_outer.hash_koalabear();

            println!("proof[{i}] vk.hash_u32()       = {:?}", vk_digest_u32);
            println!("proof[{i}] vk.hash_koalabear() = {:?}", vk_digest_kb);

            // The deferred recursion verifier hashes against the INNER program's vk_digest and
            // its committed_value_digest, both pulled from the wrapped recursion proof's public
            // values (not from the outer `vk` attached in stdin.proofs).
            let pv: &RecursionPublicValues<SP1Field> =
                recursion_proof.proof.public_values.as_slice().borrow();
            let pv_sp1_vk_digest = pv.sp1_vk_digest;
            // `committed_value_digest: [[F; 4]; 8]` of byte-valued felts; flatten to [F; 32].
            let mut pv_bytes_kb = [SP1Field::zero(); 32];
            for (j, word) in pv.committed_value_digest.iter().enumerate() {
                for (k, b) in word.iter().enumerate() {
                    pv_bytes_kb[j * 4 + k] = *b;
                }
            }
            println!("proof[{i}] pv.sp1_vk_digest    = {:?}", pv_sp1_vk_digest);
            println!("proof[{i}] pv.committed_value_digest (bytes) = {:?}", pv_bytes_kb);

            digest_a = hash_deferred_proof(&digest_a, &pv_sp1_vk_digest, &pv_bytes_kb);
            println!("proof[{i}] digest_A so far     = {:?}", digest_a);

            let proof_proof = SP1Proof::Compressed(Box::new(recursion_proof.clone()));
            let result = client.verify(&vk_outer, &proof_proof);
            tracing::info!("proof {}: {:?}", i, result);
        }
        println!("FINAL digest_A (deferred-side reconstruct): {:?}", digest_a);

        let time = tokio::time::Instant::now();
        let context = SP1Context::default();
        tracing::info!("executing the program");
        let (_, _, report) = client.execute(&elf, stdin.clone(), context.clone()).await.unwrap();
        let execute_time = time.elapsed();
        let cycles = report.total_instruction_count() as usize;
        tracing::info!("execute time: {:?}", execute_time);
        tracing::info!("Report summary: {:?}", report);

        let time = tokio::time::Instant::now();
        let vk = client.setup(&elf).await.unwrap();
        let setup_time = time.elapsed();
        tracing::info!("setup time: {:?}", setup_time);

        // Run the prover for a number of iterations.
        let mut measurements = Vec::<Measurement>::with_capacity(args.num_iterations);
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
