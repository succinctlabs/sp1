use alloy_primitives::B256;
use clap::Parser;
use rsp_client_executor::{io::ClientExecutorInput, CHAIN_ID_ETH_MAINNET};
use std::path::PathBuf;

use sp1_sdk::{include_elf, utils, ProverClient, SP1Stdin};

#[derive(Parser, Debug)]
struct Args {
    /// Whether or not to generate a proof.
    #[arg(long, default_value_t = false)]
    prove: bool,
}

fn load_input_from_cache(chain_id: u64, block_number: u64) -> ClientExecutorInput {
    let cache_path = PathBuf::from(format!("./input/{}/{}.bin", chain_id, block_number));
    let mut cache_file = std::fs::File::open(cache_path).unwrap();
    let client_input: ClientExecutorInput = bincode::deserialize_from(&mut cache_file).unwrap();

    client_input
}

fn main() {
    // Initialize the logger.
    utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    // Load the input from the cache.
    let client_input = load_input_from_cache(CHAIN_ID_ETH_MAINNET, 20526624);

    // Generate the proof.
    let client = ProverClient::new();

    // Setup the proving key and verification key.
    let (pk, vk) = client.setup(include_elf!("rsp-program"));

    // Write the block to the program's stdin.
    let mut stdin = SP1Stdin::new();
    let buffer = bincode::serialize(&client_input).unwrap();
    stdin.write_vec(buffer);

    // Only execute the program.
    let (mut public_values, execution_report) =
        client.execute(&pk.elf, stdin.clone()).run().unwrap();
    println!(
        "Finished executing the block in {} cycles",
        execution_report.total_instruction_count()
    );

    // Read the block hash.
    let block_hash = public_values.read::<B256>();
    println!("success: block_hash={block_hash}");

    // If the `prove` argument was passed in, actually generate the proof.
    // It is strongly recommended you use the network prover given the size of these programs.
    if args.prove {
        println!("Starting proof generation.");
        let proof = client.prove(&pk, stdin).run().expect("Proving should work.");
        println!("Proof generation finished.");

        client.verify(&proof, &vk).expect("proof verification should succeed");
    }
}
