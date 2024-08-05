//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be verified
//! on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --package fibonacci-script --bin prove --release
//! ```

pub mod common;

use alloy_sol_types::{sol, SolType};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sp1_sdk::{HashableKey, SP1ProofWithPublicValues, SP1VerifyingKey};
use std::path::PathBuf;

/// The arguments for the prove command.
#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct ProveArgs {
    #[clap(long, default_value = "20")]
    n: u32,

    #[clap(long, default_value = "false")]
    evm: bool,
}

/// The public values encoded as a tuple that can be easily deserialized inside Solidity.
type PublicValuesTuple = sol! {
    tuple(uint32, uint32, uint32)
};

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    // Parse the command line arguments.
    let args = ProveArgs::parse();

    // Setup the prover client.
    let (client, stdin, pk, vk) = common::init_client(args.clone());
    println!("n: {}", args.n);

    if args.evm {
        // Generate the proof.
        let proof = client
            .prove(&pk, stdin)
            .plonk()
            .run()
            .expect("failed to generate proof");
        create_plonk_fixture(&proof, &vk);
    } else {
        // Generate the proof.
        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");
        let (_, _, fib_n) =
            PublicValuesTuple::abi_decode(proof.public_values.as_slice(), false).unwrap();
        println!("Successfully generated proof!");
        println!("fib(n): {}", fib_n);

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
    }
}

/// A fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1FibonacciProofFixture {
    a: u32,
    b: u32,
    n: u32,
    vkey: String,
    public_values: String,
    proof: String,
}

/// Create a fixture for the given proof.
fn create_plonk_fixture(proof: &SP1ProofWithPublicValues, vk: &SP1VerifyingKey) {
    // Deserialize the public values.
    let bytes = proof.public_values.as_slice();
    let (n, a, b) = PublicValuesTuple::abi_decode(bytes, false).unwrap();

    // Create the testing fixture so we can test things end-ot-end.
    let fixture = SP1FibonacciProofFixture {
        a,
        b,
        n,
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(bytes)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    // The verification key is used to verify that the proof corresponds to the execution of the
    // program on the given input.
    //
    // Note that the verification key stays the same regardless of the input.
    println!("Verification Key: {}", fixture.vkey);

    // The public values are the values whicha are publically commited to by the zkVM.
    //
    // If you need to expose the inputs or outputs of your program, you should commit them in
    // the public values.
    println!("Public Values: {}", fixture.public_values);

    // The proof proves to the verifier that the program was executed with some inputs that led to
    // the give public values.
    println!("Proof Bytes: {}", fixture.proof);

    // Save the fixture to a file.
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join("fixture.json"),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");
}
