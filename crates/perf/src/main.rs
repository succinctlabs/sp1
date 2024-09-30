use std::time::{Duration, Instant};

use clap::{command, Parser, ValueEnum};
use sp1_cuda::SP1CudaProver;
use sp1_prover::components::DefaultProverComponents;
use sp1_sdk::{self, ProverClient, SP1Context, SP1Prover, SP1Stdin};
use sp1_stark::SP1ProverOpts;

#[derive(Parser, Clone)]
#[command(about = "Evaluate the performance of SP1 on programs.")]
struct PerfArgs {
    #[arg(short, long)]
    pub program: String,
    #[arg(short, long)]
    pub stdin: String,
    #[arg(short, long)]
    pub mode: ProverMode,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PerfResult {
    pub cycles: u64,
    pub execution_duration: Duration,
    pub prove_core_duration: Duration,
    pub verify_core_duration: Duration,
    pub compress_duration: Duration,
    pub verify_compressed_duration: Duration,
    pub shrink_duration: Duration,
    pub verify_shrink_duration: Duration,
    pub wrap_duration: Duration,
    pub verify_wrap_duration: Duration,
}

#[derive(Debug, Clone, ValueEnum, PartialEq, Eq)]
enum ProverMode {
    Cpu,
    Cuda,
    Network,
}

pub fn time_operation<T, F: FnOnce() -> T>(operation: F) -> (T, std::time::Duration) {
    let start = Instant::now();
    let result = operation();
    let duration = start.elapsed();
    (result, duration)
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let args = PerfArgs::parse();

    let elf = std::fs::read(args.program).expect("failed to read program");
    let stdin = std::fs::read(args.stdin).expect("failed to read stdin");
    let stdin: SP1Stdin = bincode::deserialize(&stdin).expect("failed to deserialize stdin");

    let prover = SP1Prover::<DefaultProverComponents>::new();
    let (pk, vk) = prover.setup(&elf);
    let cycles = sp1_prover::utils::get_cycles(&elf, &stdin);
    let opts = SP1ProverOpts::default();

    match args.mode {
        ProverMode::Cpu => {
            let context = SP1Context::default();
            let (_, execution_duration) =
                time_operation(|| prover.execute(&elf, &stdin, context.clone()));

            let (core_proof, prove_core_duration) =
                time_operation(|| prover.prove_core(&pk, &stdin, opts, context).unwrap());

            let (_, verify_core_duration) =
                time_operation(|| prover.verify(&core_proof.proof, &vk));

            let (compress_proof, compress_duration) =
                time_operation(|| prover.compress(&vk, core_proof, vec![], opts).unwrap());

            let (_, verify_compressed_duration) =
                time_operation(|| prover.verify_compressed(&compress_proof, &vk));

            let (shrink_proof, shrink_duration) =
                time_operation(|| prover.shrink(compress_proof, opts).unwrap());

            let (_, verify_shrink_duration) =
                time_operation(|| prover.verify_shrink(&shrink_proof, &vk));

            let (wrapped_bn254_proof, wrap_duration) =
                time_operation(|| prover.wrap_bn254(shrink_proof, opts).unwrap());

            let (_, verify_wrap_duration) =
                time_operation(|| prover.verify_wrap_bn254(&wrapped_bn254_proof, &vk));

            let result = PerfResult {
                cycles,
                execution_duration,
                prove_core_duration,
                verify_core_duration,
                compress_duration,
                verify_compressed_duration,
                shrink_duration,
                verify_shrink_duration,
                wrap_duration,
                verify_wrap_duration,
            };

            println!("{:?}", result);
        }
        ProverMode::Cuda => {
            let server = SP1CudaProver::new().expect("failed to initialize CUDA prover");

            let context = SP1Context::default();
            let (_, execution_duration) =
                time_operation(|| prover.execute(&elf, &stdin, context.clone()));

            let (core_proof, prove_core_duration) =
                time_operation(|| server.prove_core(&pk, &stdin).unwrap());

            let (_, verify_core_duration) = time_operation(|| {
                prover.verify(&core_proof.proof, &vk).expect("Proof verification failed")
            });

            let (compress_proof, compress_duration) =
                time_operation(|| server.compress(&vk, core_proof, vec![]).unwrap());

            let (_, verify_compressed_duration) =
                time_operation(|| prover.verify_compressed(&compress_proof, &vk));

            let (shrink_proof, shrink_duration) =
                time_operation(|| server.shrink(compress_proof).unwrap());

            let (_, verify_shrink_duration) =
                time_operation(|| prover.verify_shrink(&shrink_proof, &vk));

            let (wrapped_bn254_proof, wrap_duration) =
                time_operation(|| prover.wrap_bn254(shrink_proof, opts).unwrap());

            let (_, verify_wrap_duration) =
                time_operation(|| prover.verify_wrap_bn254(&wrapped_bn254_proof, &vk));

            let result = PerfResult {
                cycles,
                execution_duration,
                prove_core_duration,
                verify_core_duration,
                compress_duration,
                verify_compressed_duration,
                shrink_duration,
                verify_shrink_duration,
                wrap_duration,
                verify_wrap_duration,
            };

            println!("{:?}", result);
        }
        ProverMode::Network => {
            let prover = ProverClient::network();
            let (_, _) = time_operation(|| prover.execute(&elf, stdin.clone()));

            let (core_proof, _) =
                time_operation(|| prover.prove(&pk, stdin).compressed().run().unwrap());

            let (_, _) = time_operation(|| prover.verify(&core_proof, &vk));
        }
    };
}
