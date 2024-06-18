//! A simple CLI that wraps the gnark-ffi crate. This is called using Docker in gnark-ffi when the
//! native feature is disabled.

use sp1_recursion_gnark_ffi::ffi::{
    build_plonk_bn254, prove_plonk_bn254, test_plonk_bn254, verify_plonk_bn254,
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

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Subcommand)]
enum Command {
    BuildPlonk(BuildArgs),
    ProvePlonk(ProveArgs),
    VerifyPlonk(VerifyArgs),
    TestPlonk(TestArgs),
}

#[derive(Debug, Args)]
struct BuildArgs {
    data_dir: String,
}

#[derive(Debug, Args)]
struct ProveArgs {
    data_dir: String,
    witness_path: String,
    output_path: String,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    data_dir: String,
    proof_path: String,
    vkey_hash: String,
    committed_values_digest: String,
    output_path: String,
}

#[derive(Debug, Args)]
struct TestArgs {
    witness_json: String,
    constraints_json: String,
}

fn run_build(args: BuildArgs) {
    build_plonk_bn254(&args.data_dir);
}

fn run_prove(args: ProveArgs) {
    let proof = prove_plonk_bn254(&args.data_dir, &args.witness_path);
    let mut file = File::create(&args.output_path).unwrap();
    bincode::serialize_into(&mut file, &proof).unwrap();
}

fn run_verify(args: VerifyArgs) {
    // For proof, we read the string from file since it can be large.
    let file = File::open(&args.proof_path).unwrap();
    let proof = read_to_string(file).unwrap();
    let result = verify_plonk_bn254(
        &args.data_dir,
        proof.trim(),
        &args.vkey_hash,
        &args.committed_values_digest,
    );
    let output = match result {
        Ok(_) => "OK".to_string(),
        Err(e) => e,
    };
    let mut file = File::create(&args.output_path).unwrap();
    file.write_all(output.as_bytes()).unwrap();
}

fn run_test(args: TestArgs) {
    test_plonk_bn254(&args.witness_json, &args.constraints_json);
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::BuildPlonk(args) => run_build(args),
        Command::ProvePlonk(args) => run_prove(args),
        Command::VerifyPlonk(args) => run_verify(args),
        Command::TestPlonk(args) => run_test(args),
    }
}
