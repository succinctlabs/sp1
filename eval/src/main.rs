#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

use clap::{command, Parser};
use csv::WriterBuilder;
use serde::Serialize;
use sp1_core::runtime::{Program, Runtime};
use sp1_core::utils::{prove_simple, BabyBearBlake3, BabyBearKeccak, BabyBearPoseidon2};
use sp1_prover::utils::get_cycles;
use sp1_prover::SP1Stdin;
use std::fmt;
use std::fs::OpenOptions;
use std::io;
use std::{fs, time::Instant};

/// An identifier used to select the hash function to evaluate.
#[derive(clap::ValueEnum, Clone)]
enum HashFnId {
    Sha256,
    Poseidon,
    Blake3,
    Keccak256,
}

impl fmt::Display for HashFnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash_fn_str = match self {
            HashFnId::Sha256 => "sha-256",
            HashFnId::Poseidon => "poseidon",
            HashFnId::Blake3 => "blake3",
            HashFnId::Keccak256 => "keccak256",
        };
        write!(f, "{}", hash_fn_str)
    }
}

/// The performance report of a zkVM on a program.
#[derive(Debug, Serialize)]
pub struct PerformanceReport {
    /// The program that is being evaluated.
    pub program: String,

    /// The hash function that is being evaluated.
    pub hashfn: String,

    /// The shard size that is being evaluated.
    pub shard_size: u64,

    /// The reported number of cycles.
    pub cycles: u64,

    /// The reported speed in cycles per second.
    pub speed: f64,

    /// The reported duration of the execution in seconds.
    pub execution_duration: f64,

    /// The reported duration of the prover in seconds.
    pub prove_duration: f64,

    /// The reported duration of the verifier in seconds.
    pub verify_duration: f64,
}

#[derive(Parser, Clone)]
#[command(about = "Evaluate the performance of a zkVM on a program.")]
struct EvalArgs {
    #[arg(long)]
    pub program: String,

    #[arg(long)]
    pub hashfn: HashFnId,

    #[arg(long)]
    pub shard_size: u64,

    #[arg(long)]
    pub benchmark_path: String,

    #[arg(long)]
    pub elf_path: String,

    #[arg(long, default_value_t = 1)]
    pub runs: usize,
}

fn main() {
    let args = EvalArgs::parse();

    // Load the program.
    let elf_path = &args.elf_path;
    let elf = fs::read(elf_path).expect("Failed to read ELF file");
    let cycles = get_cycles(&elf, &SP1Stdin::new());

    // Initialize total duration counters.
    let mut total_execution_duration = 0f64;
    let mut total_prove_duration = 0f64;
    let mut total_verify_duration = 0f64;

    // Perform runs.
    let program = Program::from(&elf);
    for _ in 0..args.runs {
        let elf = fs::read(elf_path).expect("Failed to read ELF file");
        let (execution_duration, prove_duration, verify_duration) =
            run_evaluation(&args.hashfn, &program, &elf);

        // Accumulate durations.
        total_execution_duration += execution_duration;
        total_prove_duration += prove_duration;
        total_verify_duration += verify_duration;
    }

    // Calculate average durations.
    let avg_execution_duration = total_execution_duration / args.runs as f64;
    let avg_prove_duration = total_prove_duration / args.runs as f64;
    let avg_verify_duration = total_verify_duration / args.runs as f64;

    let report = PerformanceReport {
        program: args.program,
        hashfn: args.hashfn.to_string(),
        shard_size: args.shard_size,
        cycles,
        speed: cycles as f64 / avg_prove_duration,
        execution_duration: avg_execution_duration,
        prove_duration: avg_prove_duration,
        verify_duration: avg_verify_duration,
    };

    // Write the report.
    if let Err(e) = write_report(report, &args.benchmark_path) {
        eprintln!("Failed to write report: {}", e);
    }
}

fn run_evaluation(hashfn: &HashFnId, program: &Program, _elf: &[u8]) -> (f64, f64, f64) {
    // Note: While these benchmarks are useful for core proving, they are not useful for recursion
    // or end to end proving as we only support Poseidon for now.
    match hashfn {
        HashFnId::Blake3 => {
            let mut runtime = Runtime::new(program.clone());
            let execution_start = Instant::now();
            runtime.run().unwrap();
            let execution_duration = execution_start.elapsed().as_secs_f64();

            let config = BabyBearBlake3::new();
            let prove_start = Instant::now();
            let _proof = prove_simple(config.clone(), runtime);
            let prove_duration = prove_start.elapsed().as_secs_f64();

            let verify_start = Instant::now();
            // SP1ProverImpl::verify_with_config(elf, &proof, config).unwrap();
            let verify_duration = verify_start.elapsed().as_secs_f64();

            (execution_duration, prove_duration, verify_duration)
        }
        HashFnId::Poseidon => {
            let mut runtime = Runtime::new(program.clone());
            let execution_start = Instant::now();
            runtime.run().unwrap();
            let execution_duration = execution_start.elapsed().as_secs_f64();

            let config = BabyBearPoseidon2::new();
            let prove_start = Instant::now();
            let _proof = prove_simple(config.clone(), runtime);
            let prove_duration = prove_start.elapsed().as_secs_f64();

            let verify_start = Instant::now();
            // SP1ProverImpl::verify_with_config(elf, &proof, config).unwrap();
            let verify_duration = verify_start.elapsed().as_secs_f64();

            (execution_duration, prove_duration, verify_duration)
        }
        HashFnId::Keccak256 => {
            let mut runtime = Runtime::new(program.clone());
            let execution_start = Instant::now();
            runtime.run().unwrap();
            let execution_duration = execution_start.elapsed().as_secs_f64();

            let config = BabyBearKeccak::new();
            let prove_start = Instant::now();
            let _proof = prove_simple(config.clone(), runtime);
            let prove_duration = prove_start.elapsed().as_secs_f64();

            let verify_start = Instant::now();
            // SP1ProverImpl::verify_with_config(elf, &proof, config).unwrap();
            let verify_duration = verify_start.elapsed().as_secs_f64();

            (execution_duration, prove_duration, verify_duration)
        }
        _ => panic!("Unsupported hash function"),
    }
}

fn write_report(report: PerformanceReport, benchmark_path: &str) -> io::Result<()> {
    // Check if the file exists and is empty to determine if the header needs to be written.
    let write_header = fs::metadata(benchmark_path).map_or(true, |meta| meta.len() == 0);

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(benchmark_path)?;

    let mut writer = WriterBuilder::new().has_headers(false).from_writer(file);

    // Manually write the header if needed.
    if write_header {
        writer.write_record([
            "program",
            "hashfn",
            "shard_size",
            "cycles",
            "speed",
            "execution_duration",
            "prove_duration",
            "verify_duration",
        ])?;
    }

    // Serialize the report to the CSV file.
    writer.serialize(report)?;
    writer.flush()?;

    Ok(())
}
