use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, ValueEnum};
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_prover::{
    new_cuda_prover, CudaProverRecursionComponents, CudaShardProver, SP1CudaProverComponents,
    RECURSION_TRACE_ALLOCATION, SHRINK_TRACE_ALLOCATION,
};
use sp1_hypercube::{
    inner_perm,
    prover::{AirProver, ProverSemaphore},
    SP1PcsProofInner,
};
use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext};
use sp1_prover::{
    recursion::{compose_program_from_input, recursive_verifier, shrink_program_from_input},
    shapes::SP1RecursionProofShape,
    SP1ProverComponents,
};
use sp1_recursion_circuit::{machine::SP1CompressWithVKeyWitnessValues, witness::Witnessable};
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_executor::Executor;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Mode {
    /// Compose program at arity 2 (truncates the loaded compose witness to 2).
    #[value(name = "2")]
    Arity2,
    /// Compose program at arity 3 (truncates the loaded compose witness to 3).
    #[value(name = "3")]
    Arity3,
    /// Compose program at arity 4 (uses the loaded compose witness as-is).
    #[value(name = "4")]
    Arity4,
    /// Shrink program (uses the loaded shrink witness, which has arity 1).
    Shrink,
}

impl Mode {
    fn compose_arity(self) -> Option<usize> {
        match self {
            Mode::Arity2 => Some(2),
            Mode::Arity3 => Some(3),
            Mode::Arity4 => Some(4),
            Mode::Shrink => None,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Run a recursion proving stage (compose at arity 2/3/4, or shrink) using a real input"
)]
struct Args {
    /// Which proving stage to run.
    #[arg(long, value_enum)]
    pub mode: Mode,
    /// Path to the bincode-serialized SP1CompressWithVKeyWitnessValues file. Defaults to the
    /// per-mode location written by the prover when the relevant `SP1_RECORD_*_INPUT` env var
    /// is set.
    #[arg(long)]
    pub input: Option<String>,
    /// Whether to enable vk verification in the recursion circuit.
    #[arg(long, default_value_t = true)]
    pub vk_verification: bool,
    /// Number of timed setup+prove repetitions. A single untimed warmup run is always done
    /// before the timed runs.
    #[arg(long, short = 'r', default_value_t = 1)]
    pub repetitions: usize,
}

fn default_input_path(mode: Mode) -> &'static str {
    match mode {
        Mode::Arity2 | Mode::Arity3 | Mode::Arity4 => {
            "sp1-gpu/crates/perf/recursion_records/max_arity_input.bin"
        }
        Mode::Shrink => "sp1-gpu/crates/perf/recursion_records/shrink_input.bin",
    }
}

#[tokio::main]
#[allow(clippy::print_stdout)]
async fn main() {
    let args = Args::parse();

    dotenv::dotenv().ok();
    sp1_gpu_tracing::init_tracer();

    let mode = args.mode;
    let input_path = args.input.unwrap_or_else(|| default_input_path(mode).to_string());

    // Load the bin file and deserialize.
    let bytes = std::fs::read(&input_path).expect("failed to read input file");
    let mut input: SP1CompressWithVKeyWitnessValues<SP1PcsProofInner> =
        bincode::deserialize(&bytes).expect("failed to deserialize recursion witness");

    let original_arity = input.compress_val.vks_and_proofs.len();

    if let Some(target_arity) = mode.compose_arity() {
        assert!(
            target_arity <= original_arity,
            "compose arity ({}) must be <= the loaded witness arity ({})",
            target_arity,
            original_arity
        );
        tracing::info!(
            "loaded compose witness with arity {}, truncating to {}",
            original_arity,
            target_arity
        );
        input.compress_val.vks_and_proofs.truncate(target_arity);
        input.merkle_val.vk_merkle_proofs.truncate(target_arity);
        input.merkle_val.values.truncate(target_arity);
        // Truncated chain is no longer "complete" — set the flag accordingly so the circuit
        // branches match the dummy input the prover normally builds programs from.
        input.compress_val.is_complete = false;
    } else {
        assert_eq!(original_arity, 1, "shrink witness must have arity 1, found {}", original_arity);
        tracing::info!("loaded shrink witness with arity 1");
    }

    assert!(args.repetitions >= 1, "--repetitions must be >= 1");

    let machine = RiscvAir::machine();
    let vk_verification = args.vk_verification;
    let repetitions = args.repetitions;

    sp1_gpu_cudart::spawn(move |t| async move {
        let permits = ProverSemaphore::new(1);

        // The compress verifier is used to build the recursive verifier inside both the compose
        // and shrink programs. The shrink program is just an arity-1 verifier of a compressed
        // proof, so it embeds a recursive verifier of the compress machine.
        let compress_verifier = SP1CudaProverComponents::compress_verifier();
        let recursive_compress_verifier = recursive_verifier::<SP1GlobalContext, _, InnerConfig>(
            compress_verifier.shard_verifier(),
        );

        // Build the program for this mode.
        let build_start = Instant::now();
        let program = match mode.compose_arity() {
            Some(_) => {
                let reduce_shape = SP1RecursionProofShape::retrieve_or_compute_reduce_shape(
                    machine,
                    original_arity,
                );
                let mut program = compose_program_from_input(
                    &recursive_compress_verifier,
                    vk_verification,
                    &input,
                );
                program.shape = Some(reduce_shape.shape.clone());
                program
            }
            None => {
                shrink_program_from_input(&recursive_compress_verifier, vk_verification, &input)
            }
        };
        let program = Arc::new(program);
        tracing::info!("{:?} program built in {:.3}s", mode, build_start.elapsed().as_secs_f64());

        // Build the prover for this mode. Compose uses RECURSION_TRACE_ALLOCATION; shrink uses
        // the smaller SHRINK_TRACE_ALLOCATION (matching the production worker builder).
        let (prover_verifier, trace_alloc) = match mode {
            Mode::Shrink => (SP1CudaProverComponents::shrink_verifier(), SHRINK_TRACE_ALLOCATION),
            _ => (compress_verifier.clone(), RECURSION_TRACE_ALLOCATION),
        };
        let prover: Arc<CudaShardProver<_, CudaProverRecursionComponents>> =
            Arc::new(new_cuda_prover(&prover_verifier, trace_alloc, 4, false, t.clone()).await);

        // Build witness stream.
        let mut witness_stream = Vec::new();
        Witnessable::<InnerConfig>::write(&input, &mut witness_stream);

        // Execute the program to generate the execution record.
        let exec_start = Instant::now();
        let mut runtime =
            Executor::<SP1Field, SP1ExtensionField, _>::new(program.clone(), inner_perm());
        runtime.witness_stream = witness_stream.into();
        runtime.run().expect("recursion executor failed");
        let mut record = runtime.record;
        tracing::info!("recursion executor finished in {:.3}s", exec_start.elapsed().as_secs_f64());

        // Generate dependencies on the record. The compose pipeline does this; the shrink
        // pipeline in production skips it, so match that behavior.
        if matches!(mode, Mode::Arity2 | Mode::Arity3 | Mode::Arity4) {
            compress_verifier.machine().generate_dependencies(std::iter::once(&mut record), None);
        }

        // Warmup run (untimed) followed by `repetitions` timed setup+prove iterations. The
        // returned `ProverPermit` holds a slot in the single-permit semaphore until it is
        // dropped, so each call must end its scope (releasing the permit) before the next one
        // tries to acquire.
        tracing::info!("warmup run starting");
        let warmup_start = Instant::now();

        let (_vk, _proof, _) = prover
            .setup_and_prove_shard(program.clone(), record.clone(), None, permits.clone())
            .await;

        tracing::info!("warmup run finished in {:.3}s", warmup_start.elapsed().as_secs_f64());

        let mut timings = Vec::with_capacity(repetitions);
        for i in 0..repetitions {
            let prove_start = Instant::now();

            let (_vk, _proof, _) = prover
                .setup_and_prove_shard(program.clone(), record.clone(), None, permits.clone())
                .await;

            let elapsed = prove_start.elapsed().as_secs_f64();
            tracing::info!("{:?} run {}/{}: {elapsed:.3}s", mode, i + 1, repetitions);
            timings.push(elapsed);
        }

        let total: f64 = timings.iter().sum();
        let avg = total / timings.len() as f64;
        let min = timings.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = timings.iter().cloned().fold(0.0_f64, f64::max);
        tracing::info!(
            "{:?} setup+prove over {} runs: avg={:.3}s min={:.3}s max={:.3}s",
            mode,
            repetitions,
            avg,
            min,
            max
        );
        println!(
            "mode={:?} repetitions={} avg={:.3}s min={:.3}s max={:.3}s",
            mode, repetitions, avg, min, max
        );
    })
    .await
    .unwrap();
}
