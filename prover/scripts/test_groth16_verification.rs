#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

use std::path::PathBuf;
use std::{fs::File, io::Write};

use clap::Parser;
use sp1_prover::Groth16Proof;
use sp1_recursion_gnark_ffi::{convert, verify};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: String,
}

const EXAMPLE_PROOF: &str = include_str!("artifacts/example_proof.json");
const EXAMPLE_VKEY: &[u8] = include_bytes!("artifacts/example_vk_groth16.bin");

/// Test Groth16 verification and conversion to Solidity formatting with the Gnark FFI bindings.
pub fn main() {
    sp1_core::utils::setup_logger();
    std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");

    // Temporary directory for build_dir.
    let temp_dir = tempfile::tempdir().unwrap();
    let build_dir = temp_dir.into_path();

    // Write the example vkey bytes to build_dir/vk_groth16.bin, which is where the verifier expects the vkey to be.
    let mut file = File::create(PathBuf::from(&build_dir).join("vk_groth16.bin")).unwrap();
    file.write_all(EXAMPLE_VKEY).unwrap();

    // Read the valid proof from the JSON file.
    let proof: Groth16Proof = serde_json::from_str(EXAMPLE_PROOF).unwrap();

    tracing::info!("verify gnark proof");
    let verified = verify(&proof, &build_dir);
    assert!(verified);

    tracing::info!("convert gnark proof");
    let solidity_proof = convert(proof.clone(), &build_dir);

    println!("{:?}", proof);
    println!("solidity proof: {:?}", solidity_proof);
}
