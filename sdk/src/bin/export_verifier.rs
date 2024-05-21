use clap::Parser;
use sp1_sdk::artifacts::export_solidity_groth16_verifier;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, default_value = "../contracts/src")]
    output_dir: PathBuf,
}

fn main() {
    let args = Args::parse();
    export_solidity_groth16_verifier(args.output_dir).expect("Failed to export verifier");
}
