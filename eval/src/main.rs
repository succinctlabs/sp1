use clap::{command, Parser};
use csv::WriterBuilder;
use serde::Serialize;
use sp1_core::runtime::{Program, Runtime};
use sp1_core::utils::{get_cycles, prove_core, BabyBearBlake3, BabyBearKeccak, BabyBearPoseidon2};
use sp1_core::{SP1ProofWithIO, SP1Stdin, SP1Stdout, SP1Verifier};
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

impl HashFnId {
    fn to_string(&self) -> String {
        match self {
            HashFnId::Sha256 => "sha-256".to_string(),
            HashFnId::Poseidon => "poseidon".to_string(),
            HashFnId::Blake3 => "blake3".to_string(),
            HashFnId::Keccak256 => "keccak256".to_string(),
        }
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
}

fn main() {
    let args = EvalArgs::parse();

    let elf_path = args.elf_path;
    println!("ELF path: {}", elf_path);

    let benchmark_path = args.benchmark_path;
    println!("Benchmark path: {}", benchmark_path);

    // Read the program from the file system.
    let program = Program::from_elf(&elf_path);
    let elf = fs::read(&elf_path).unwrap();

    // Compute some statistics.
    let cycles = get_cycles(program.clone());
    println!("sp1 cycles: {}", cycles);

    // Setup the prover.
    std::env::set_var("SHARD_SIZE", format!("{}", args.shard_size));
    if args.shard_size & (args.shard_size - 1) != 0 {
        panic!("shard_size must be a power of 2");
    }

    let (execution_duration, prove_duration, verify_duration) = match args.hashfn {
        HashFnId::Blake3 => {
            // Execute the runtime.
            let mut runtime = Runtime::new(program);
            let execution_start = Instant::now();
            runtime.run();
            let execution_duration = execution_start.elapsed();

            // Generate the proof.
            let config = BabyBearBlake3::new();
            let prove_start = Instant::now();
            let proof = prove_core(config, runtime);
            let prove_duration = prove_start.elapsed();
            let proof = SP1ProofWithIO {
                stdin: SP1Stdin::new(),
                stdout: SP1Stdout::new(),
                proof,
            };

            // Verify the proof.
            let config = BabyBearBlake3::new();
            let verify_start = Instant::now();
            SP1Verifier::verify_with_config(&elf, &proof, config).unwrap();
            let verify_duration = verify_start.elapsed();

            (execution_duration, prove_duration, verify_duration)
        }
        HashFnId::Poseidon => {
            // Execute the runtime.
            let mut runtime = Runtime::new(program);
            let execution_start = Instant::now();
            runtime.run();
            let execution_duration = execution_start.elapsed();

            // Generate the proof.
            let config = BabyBearPoseidon2::new();
            let prove_start = Instant::now();
            let proof = prove_core(config, runtime);
            let prove_duration = prove_start.elapsed();
            let proof = SP1ProofWithIO {
                stdin: SP1Stdin::new(),
                stdout: SP1Stdout::new(),
                proof,
            };

            // Verify the proof.
            let config = BabyBearPoseidon2::new();
            let verify_start = Instant::now();
            SP1Verifier::verify_with_config(&elf, &proof, config).unwrap();
            let verify_duration = verify_start.elapsed();

            (execution_duration, prove_duration, verify_duration)
        }
        HashFnId::Keccak256 => {
            // Execute the runtime.
            let mut runtime = Runtime::new(program);
            let execution_start = Instant::now();
            runtime.run();
            let execution_duration = execution_start.elapsed();

            // Generate the proof.
            let config = BabyBearKeccak::new();
            let prove_start = Instant::now();
            let proof = prove_core(config, runtime);
            let prove_duration = prove_start.elapsed();
            let proof = SP1ProofWithIO {
                stdin: SP1Stdin::new(),
                stdout: SP1Stdout::new(),
                proof,
            };

            // Verify the proof.
            let config = BabyBearKeccak::new();
            let verify_start = Instant::now();
            SP1Verifier::verify_with_config(&elf, &proof, config).unwrap();
            let verify_duration = verify_start.elapsed();

            (execution_duration, prove_duration, verify_duration)
        }
        _ => panic!("unsupported hash function"),
    };

    let report = PerformanceReport {
        program: args.program,
        hashfn: args.hashfn.to_string(),
        shard_size: args.shard_size,
        cycles,
        speed: (cycles as f64) / prove_duration.as_secs_f64(),
        execution_duration: execution_duration.as_secs_f64(),
        prove_duration: prove_duration.as_secs_f64(),
        verify_duration: verify_duration.as_secs_f64(),
    };

    if let Err(e) = write_report(report, &benchmark_path) {
        eprintln!("Failed to write report: {}", e);
    }
}

fn write_report(report: PerformanceReport, benchmark_path: &str) -> io::Result<()> {
    // Check if the file exists and is empty to determine if the header needs to be written.
    let write_header = fs::metadata(benchmark_path).map_or(true, |meta| meta.len() == 0);

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(benchmark_path)?;

    let mut writer = WriterBuilder::new().has_headers(false).from_writer(file);

    // Manually write the header if needed.
    if write_header {
        writer.write_record(&[
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
