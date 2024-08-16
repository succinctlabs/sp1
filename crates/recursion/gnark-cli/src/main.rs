//! A simple CLI that wraps the gnark-ffi crate. This is called using Docker in gnark-ffi when the
//! native feature is disabled.

use sp1_recursion_gnark_ffi::{
    ffi::{
        build_groth16_bn254, build_plonk_bn254, test_groth16_bn254, test_plonk_bn254,
        verify_groth16_bn254, verify_plonk_bn254,
    },
    ProofBn254,
};

use clap::{Args, Parser, Subcommand};
use std::{
    fs::File,
    io::{read_to_string, Write},
};

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Build(BuildArgs),
    Prove(ProveArgs),
    Verify(VerifyArgs),
    Test(TestArgs),
}

#[derive(Debug, Args)]
struct BuildArgs {
    data_dir: String,
    #[arg(short, long)]
    system: String,
}

#[derive(Debug, Args)]
struct ProveArgs {
    data_dir: String,
    witness_path: String,
    output_path: String,
    #[arg(short, long)]
    system: String,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    data_dir: String,
    proof_path: String,
    vkey_hash: String,
    committed_values_digest: String,
    output_path: String,
    #[arg(short, long)]
    system: String,
}

#[derive(Debug, Args)]
struct TestArgs {
    witness_json: String,
    constraints_json: String,
    #[arg(short, long)]
    system: String,
}

fn run_build(args: BuildArgs) {
    match args.system.as_str() {
        "plonk" => build_plonk_bn254(&args.data_dir),
        "groth16" => build_groth16_bn254(&args.data_dir),
        _ => panic!("Unsupported system: {}", args.system),
    }
}

fn run_prove(args: ProveArgs) {
    let proof = match args.system.as_str() {
        "plonk" => prove_plonk_bn254(&args.data_dir, &args.witness_path),
        "groth16" => prove_groth16_bn254(&args.data_dir, &args.witness_path),
        _ => panic!("Unsupported system: {}", args.system),
    };
    let mut file = File::create(&args.output_path).unwrap();
    bincode::serialize_into(&mut file, &proof).unwrap();
}

fn prove_plonk_bn254(data_dir: &str, witness_path: &str) -> ProofBn254 {
    ProofBn254::Plonk(sp1_recursion_gnark_ffi::ffi::prove_plonk_bn254(data_dir, witness_path))
}

fn prove_groth16_bn254(data_dir: &str, witness_path: &str) -> ProofBn254 {
    ProofBn254::Groth16(sp1_recursion_gnark_ffi::ffi::prove_groth16_bn254(data_dir, witness_path))
}

fn run_verify(args: VerifyArgs) {
    let file = File::open(&args.proof_path).unwrap();
    let proof = read_to_string(file).unwrap();
    let result = match args.system.as_str() {
        "plonk" => verify_plonk_bn254(
            &args.data_dir,
            proof.trim(),
            &args.vkey_hash,
            &args.committed_values_digest,
        ),
        "groth16" => verify_groth16_bn254(
            &args.data_dir,
            proof.trim(),
            &args.vkey_hash,
            &args.committed_values_digest,
        ),
        _ => panic!("Unsupported system: {}", args.system),
    };
    let output = match result {
        Ok(_) => "OK".to_string(),
        Err(e) => e,
    };
    let mut file = File::create(&args.output_path).unwrap();
    file.write_all(output.as_bytes()).unwrap();
}

fn run_test(args: TestArgs) {
    match args.system.as_str() {
        "plonk" => test_plonk_bn254(&args.witness_json, &args.constraints_json),
        "groth16" => test_groth16_bn254(&args.witness_json, &args.constraints_json),
        _ => panic!("Unsupported system: {}", args.system),
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Build(args) => run_build(args),
        Command::Prove(args) => run_prove(args),
        Command::Verify(args) => run_verify(args),
        Command::Test(args) => run_test(args),
    }
}
