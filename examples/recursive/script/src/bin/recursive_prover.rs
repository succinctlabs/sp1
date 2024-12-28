//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use clap::Parser;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use recursive_lib::CircuitInput;
use sp1_sdk::SP1Proof;
use sp1_sdk::HashableKey;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const RECURSIVE_ELF: &[u8] = include_elf!("recursive-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long, default_value = "20")]
    n: u32,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }
    assert_eq!(args.n > 0, true, "n must be greater than 0");
    let test_public_values = (0..args.n).map(|i| 100 + i).collect::<Vec<_>>();

    if args.execute {
        let client = ProverClient::new();
        let (recursive_prover_pk, recursive_prover_vk) = client.setup(RECURSIVE_ELF);

        // For the very first prover 
        // initialized public and private values for the very first prover 
        let mut vkey_hash = [0u32; 8];
        let mut public_input_merkle_root = [0u8; 32];
        let mut public_value = test_public_values[0];
        let mut private_value = 0u32;
        let mut witness: Vec<u32> = vec![];
        let mut circuit_input = CircuitInput::new(public_input_merkle_root, public_value, private_value, witness);

        // just fill in STDIN
        let mut stdin = SP1Stdin::new();
        // write sequence number
        stdin.write(&(0 as u32));
        // write vkey u32 hash
        stdin.write(&vkey_hash);
        // write circuit input 
        stdin.write(&circuit_input);
        // generate proof for the very first prover
        let mut last_prover_proof = client
            .prove(&recursive_prover_pk, stdin)
            .compressed()
            .run()
            .expect("proving failed");
        println!("## Generating proof for the very first prover succeeds!");

        // For the rest of the provers
        for seq in 1..args.n {
            // public and private values for the rest of provers
            vkey_hash = recursive_prover_vk.hash_u32();
            public_input_merkle_root = last_prover_proof.public_values.read::<[u8; 32]>();
            private_value = last_prover_proof.public_values.read::<u32>();
            public_value = test_public_values[seq as usize];
            witness = test_public_values[..seq as usize].to_vec();
            circuit_input = CircuitInput::new(public_input_merkle_root, public_value, private_value, witness);
            
            // just fill in STDIN
            stdin = SP1Stdin::new();
            stdin.write(&(seq as u32));
            stdin.write(&vkey_hash);
            stdin.write(&circuit_input);
            let SP1Proof::Compressed(proof) = last_prover_proof.proof else {
                panic!()
            };
            // write proof and vkey as private value
            stdin.write_proof(*proof, recursive_prover_vk.vk.clone());
            last_prover_proof = client
                .prove(&recursive_prover_pk, stdin)
                .compressed()
                .run()
                .expect("proving failed");
            println!("## Generating proof for one of the rest provers succeeds!");
        }

            
    } else {
        unimplemented!();
    }
}
