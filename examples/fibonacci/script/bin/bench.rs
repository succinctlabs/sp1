use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::Duration;
use anyhow::Context;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sp1_sdk::{utils, ProverClient, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn get_time() -> Duration {
    std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).expect("get millis error")
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    cmd: Commands
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Run {
        output: String,
    },
    Compare {
        base: String,
        head: String,
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct BenchResult {
    cycles_per_msec: f64,
}

fn main() {
    let args = Args::parse();

    match args.cmd {
        Commands::Run{output} => run_bench(&output),
        Commands::Compare{base, head} => run_comp(&base, &head)
    }
}

fn read_result(path: &String) -> anyhow::Result<BenchResult> {
    let file = File::open(path)?;
    let result: BenchResult = serde_json::from_reader(&file)?;
    Ok(result)
}

fn run_comp(base: &String, head: &String) {
    let base_result = read_result(base).context(format!("failed to read {}", base));
    let head_result = read_result(head).context(format!("failed to read {}", head));

    println!("base: {:?}", base_result);
    println!("head: {:?}", head_result);
}

fn run_bench(output: &String) {
    // Setup logging.
    utils::setup_logger();

    // Create an input stream and write '500' to it.
    let n = 1u32;

    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    // Generate the proof for the given program and input.
    let client = ProverClient::new();
    let (pk, _vk) = client.setup(ELF);

    let now = get_time();
    let _proof = client.prove(&pk, stdin.clone()).run().unwrap();
    let prove_millis = (get_time() - now).as_millis();
    println!("prove millis: {}", prove_millis);

    let exec_result = client.execute(&ELF, stdin.clone()).run().unwrap();
    let exec_report = &exec_result.1;
    let exec_cycles = exec_report.total_cycles;
    println!("execute total_cycles: {}", exec_cycles);

    let cycles_per_msec = exec_cycles as f64 / prove_millis as f64;
    println!("cycles per msec: {:.2}", cycles_per_msec);

    let result = BenchResult{cycles_per_msec};
    let mut output_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(output)
        .unwrap();

    let serialized = serde_json::to_string(&result).unwrap();
    output_file.write_all(serialized.as_bytes()).unwrap();
}
