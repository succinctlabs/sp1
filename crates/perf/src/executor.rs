use std::time::{Duration, Instant};

use clap::{command, Parser};
use p3_baby_bear::BabyBear;
use sp1_core_executor::{Executor, ExecutorMode, Program};
use sp1_core_machine::shape::CoreShapeConfig;
use sp1_sdk::{self, SP1Stdin};
use sp1_stark::SP1ProverOpts;

#[derive(Parser, Clone)]
#[command(about = "Evaluate the performance of SP1 on programs.")]
struct PerfArgs {
    /// The program to evaluate.
    #[arg(short, long)]
    pub program: String,

    /// The input to the program being evaluated.
    #[arg(short, long)]
    pub stdin: String,

    /// The executor mode to use.
    #[arg(short, long)]
    pub executor_mode: ExecutorMode,
}

#[derive(Default, Debug, Clone)]
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

pub fn time_operation<T, F: FnOnce() -> T>(operation: F) -> (T, std::time::Duration) {
    let start = Instant::now();
    let result = operation();
    let duration = start.elapsed();
    (result, duration)
}

fn calculate_mhz(cycles: u64, duration: Duration) -> f64 {
    cycles as f64 / 1_000_000.0 / duration.as_secs_f64()
}

fn run_and_report<F>(mode: &str, executor: &mut Executor<BabyBear>, run_fn: F)
where
    F: FnOnce(&mut Executor<BabyBear>),
{
    let (_, duration) = time_operation(|| run_fn(executor));
    let cycles = executor.state.global_clk;
    println!("{} mode:", mode);
    println!("cycles: {}", cycles);
    println!("MHZ: {}", calculate_mhz(cycles, duration));
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let args = PerfArgs::parse();

    let elf = std::fs::read(args.program).expect("failed to read program");
    let stdin = std::fs::read(args.stdin).expect("failed to read stdin");
    let stdin: SP1Stdin = bincode::deserialize(&stdin).expect("failed to deserialize stdin");

    let opts = SP1ProverOpts::auto();

    let mut program = Program::from(&elf).expect("failed to parse program");
    let shape_config = CoreShapeConfig::<BabyBear>::default();
    shape_config.fix_preprocessed_shape(&mut program).unwrap();
    let maximal_shapes = shape_config
        .maximal_core_shapes(opts.core_opts.shard_size.ilog2() as usize)
        .into_iter()
        .collect::<Vec<_>>();

    let mut executor = Executor::new(program, opts.core_opts);
    executor.maximal_shapes = Some(maximal_shapes);
    executor.write_vecs(&stdin.buffer);
    for (proof, vkey) in stdin.proofs.iter() {
        executor.write_proof(proof.clone(), vkey.clone());
    }

    match args.executor_mode {
        ExecutorMode::Simple => run_and_report("Simple", &mut executor, |e| e.run_fast()),
        ExecutorMode::Checkpoint => {
            run_and_report("Checkpoint", &mut executor, |e| e.run_checkpoint(true))
        }
        ExecutorMode::Trace => run_and_report("Trace", &mut executor, |e| e.run()),
        ExecutorMode::ShapeCollection => unimplemented!(),
    }
}
