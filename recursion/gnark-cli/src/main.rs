use sp1_recursion_gnark_ffi::ffi::{prove_plonk_bn254, verify_plonk_bn254};

use clap::{Args, Parser, Subcommand};
use std::{
    ffi::{c_char, CString},
    fs::File,
    io::Write,
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
    proof: String,
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
    todo!();
}

fn run_prove(args: ProveArgs) {
    let proof = prove_plonk_bn254(&args.data_dir, &args.witness_path);
    let mut file = File::create(&args.output_path).unwrap();
    bincode::serialize_into(&mut file, &proof).unwrap();
}

fn run_verify(args: VerifyArgs) {
    // dbg!(args);
    // todo!();
    let result = verify_plonk_bn254(
        &args.data_dir,
        &args.proof,
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
    dbg!(args);
    todo!();
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
