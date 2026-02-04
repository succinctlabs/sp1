use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

use alloy_primitives::B256;
use clap::Parser;
use rsp_client_executor::{io::ClientExecutorInput, CHAIN_ID_ETH_MAINNET};
use std::path::PathBuf;

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("rsp-program");

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

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    // Load the input from the cache.
    let client_input = load_input_from_cache(CHAIN_ID_ETH_MAINNET, 21740137);
    let mut stdin = SP1Stdin::default();
    let buffer = bincode::serialize(&client_input).unwrap();
    stdin.write_vec(buffer);


    let client = ProverClient::from_env().await;
    let now = std::time::Instant::now();
    let (mut public_values, report) = client.execute(ELF, stdin.clone()).await.unwrap();

    println!("total elapsed: {:?}", now.elapsed());

    println!("Full execution report:\n{:?}", report);
    println!("Cycles: {:?}", report.total_instruction_count());

    let block_hash = public_values.read::<B256>();
    println!("success: block_hash={block_hash}");
}
