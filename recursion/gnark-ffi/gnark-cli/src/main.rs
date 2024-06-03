mod babybear;

use std::ffi::{c_char, CString};
use clap::{Args, Parser, Subcommand};

#[allow(warnings, clippy::all)]
mod bind {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
use bind::*;

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
}

#[derive(Debug, Args)]
struct VerifyArgs {
    data_dir: String,
    proof: String,
    vkey_hash: String,
    committed_values_digest: String,
}

#[derive(Debug, Args)]
struct TestArgs {
    witness_json: String,
    constraints_json: String,
}

fn run_build(args: BuildArgs) {
    let c_str = CString::new(args.data_dir).expect("CString::new failed");

    unsafe {
        bind::BuildPlonkBn254(c_str.as_ptr() as *mut c_char);
    }
}

fn run_prove(args: ProveArgs) {
    dbg!(args);
    todo!();
}

fn run_verify(args: VerifyArgs) {
    dbg!(args);
    todo!();
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
