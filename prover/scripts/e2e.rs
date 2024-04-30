#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

use std::path::PathBuf;

use clap::Parser;
use sp1_core::io::SP1Stdin;
use sp1_core::utils::setup_logger;
use sp1_prover::build::build_groth16_artifacts;
use sp1_prover::SP1Prover;
use sp1_recursion_circuit::stark::build_wrap_circuit;
use sp1_recursion_circuit::witness::Witnessable;
use sp1_recursion_compiler::ir::Witness;
use sp1_recursion_gnark_ffi::Groth16Prover;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: PathBuf,
}

pub fn main() {
    setup_logger();
    let args = Args::parse();
    build_groth16_artifacts(args.build_dir);
}
