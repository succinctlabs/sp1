#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use clap::Parser;
use sp1_prover::Groth16Proof;
use sp1_recursion_gnark_ffi::{convert, verify};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: String,
}

pub fn main() {
    sp1_core::utils::setup_logger();
    std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");

    let args = Args::parse();

    let mut file =
        File::open(PathBuf::from(args.build_dir.clone()).join("test_proof_input.json")).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let proof: Groth16Proof = serde_json::from_str(&contents).unwrap();

    tracing::info!("verify gnark proof");
    let verified = verify(proof.clone(), args.build_dir.clone().into());
    assert!(verified);

    tracing::info!("convert gnark proof");
    let solidity_proof = convert(proof.clone(), args.build_dir.clone().into());

    // tracing::info!("sanity check plonk bn254 build");
    // PlonkBn254Prover::build(
    //     constraints.clone(),
    //     witness.clone(),
    //     args.build_dir.clone().into(),
    // );

    // tracing::info!("sanity check plonk bn254 prove");
    // let proof = PlonkBn254Prover::prove(witness.clone(), args.build_dir.clone().into());

    println!("{:?}", proof);
    println!("solidity proof: {:?}", solidity_proof);
}
