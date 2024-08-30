// use reth_primitives::B256;
use rsp_client_executor::{
    io::ClientExecutorInput, CHAIN_ID_ETH_MAINNET,
};
use sp1_sdk::{ProverClient, SP1Stdin};
use std::path::PathBuf;
use tracing_subscriber::{
    filter::EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

fn main() -> () {
   // Initialize the logger.
    tracing_subscriber::registry().with(fmt::layer()).with(EnvFilter::from_default_env()).init();

    let client_input = try_load_input_from_cache(
        &PathBuf::from("input/"),
        CHAIN_ID_ETH_MAINNET,
        20526624,
    ).unwrap();

    // Generate the proof.
    let client = ProverClient::new();

    // Setup the proving key and verification key.
    let (pk, vk) = client.setup(include_bytes!("../../eth-program/elf/riscv32im-succinct-zkvm-elf"));

    // Execute the block inside the zkVM.
    let mut stdin = SP1Stdin::new();
    let buffer = bincode::serialize(&client_input).unwrap();
    stdin.write_vec(buffer);

    // Only execute the program.
    let (mut public_values, execution_report) =
        client.execute(&pk.elf, stdin.clone()).run().unwrap();
    println!("Finished executing the block in {} ccycles", execution_report.total_instruction_count());

    // Read the block hash.
    // let block_hash = public_values.read::<B256>();
    // println!("success: block_hash={block_hash}");

    // Actually generate the proof. It is strongly recommended you use the network prover
    // given the size of these programs.
    // println!("Starting proof generation.");
    // let proof = client.prove(&pk, stdin).compressed().run().expect("Proving should work.");
    // println!("Proof generation finished.");

    // client.verify(&proof, &vk).expect("proof verification should succeed");
}

fn try_load_input_from_cache(
    cache_dir:&PathBuf,
    chain_id: u64,
    block_number: u64,
) -> eyre::Result<ClientExecutorInput> {
    let cache_path = PathBuf::from(format!("./input/{}/{}.bin", chain_id, block_number));
    println!("pwd: {:?}", std::env::current_dir());
    
    if cache_path.exists() {
        // TODO: prune the cache if invalid instead
        let mut cache_file = std::fs::File::open(cache_path)?;
        let client_input: ClientExecutorInput = bincode::deserialize_from(&mut cache_file)?;

        Ok(client_input)
    } else {
        Err(eyre::eyre!("cache not found"))
    }
}
