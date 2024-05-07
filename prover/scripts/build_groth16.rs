#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

use std::path::PathBuf;

use clap::Parser;
use sp1_core::utils::setup_logger;
use sp1_prover::build::build_groth16_artifacts_with_dummy;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: PathBuf,
}

pub fn main() {
    setup_logger();
    let args = Args::parse();
    build_groth16_artifacts_with_dummy(args.build_dir);
}
