use std::path::PathBuf;

use clap::Parser;
use sp1_core_machine::utils::setup_logger;
use sp1_prover::build::build_groth16_bn254_contracts;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    build_dir: PathBuf,
}

pub fn main() {
    setup_logger();
    let args = Args::parse();
    build_groth16_bn254_contracts(&args.build_dir).expect("failed to build groth16 contracts");
}
