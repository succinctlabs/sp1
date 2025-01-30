use std::path::PathBuf;

use clap::Parser;
use sp1_core_machine::utils::setup_logger;
use sp1_prover::build::build_plonk_bn254_artifacts_with_dummy;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    build_dir: PathBuf,
}

pub fn main() {
    setup_logger();
    let args = Args::parse();
    build_plonk_bn254_artifacts_with_dummy(args.build_dir);
}
