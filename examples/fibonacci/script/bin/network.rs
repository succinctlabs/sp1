use sp1_sdk::{
    include_elf,
    network_v2::{Error, FulfillmentStrategy, NetworkProver, DEFAULT_PROVER_NETWORK_RPC},
    utils, Prover, SP1Stdin,
};
use std::env;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci-program");

#[tokio::main]
async fn main() {
    // Setup logging.
    utils::setup_logger();

    // Read environment variables.
    let private_key =
        env::var("SP1_PRIVATE_KEY").expect("SP1_PRIVATE_KEY must be set for remote proving");
    let rpc_url =
        env::var("PROVER_NETWORK_RPC").unwrap_or_else(|_| DEFAULT_PROVER_NETWORK_RPC.to_string());

    // Create the network prover client.
    let prover = NetworkProver::new(&private_key)
        .with_rpc_url(rpc_url)
        .with_cycle_limit(20_000) // Set a manual cycle limit
        .with_timeout_secs(3600) // Set a 1 hour timeout
        .with_strategy(FulfillmentStrategy::Hosted) // Use the hosted strategy
        .skip_simulation(); // Skip simulation since we know our cycle requirements

    // Setup proving key and verifying key.
    let (pk, vk) = prover.setup(ELF);

    // Write the input to the stdin.
    let mut stdin = SP1Stdin::new();
    stdin.write(&1000u32);

    // Send the proof request to the prover network, with examples of how to handle errors.
    let proof_result = prover.prove(&pk, stdin).await;
    let mut proof = match proof_result {
        Ok(proof) => proof,
        Err(e) => match e {
            Error::RequestUnexecutable => {
                eprintln!("Error executing: {}", e);
                std::process::exit(1);
            }
            Error::RequestUnfulfillable => {
                eprintln!("Error proving: {}", e);
                std::process::exit(1);
            }
            _ => {
                eprintln!("Unexpected error: {}", e);
                std::process::exit(1);
            }
        },
    };

    println!("generated proof");

    // Read and verify the output.
    //
    // Note that this output is read from values committed to in the program using
    // `sp1_zkvm::io::commit`.
    let _ = proof.public_values.read::<u32>();
    let a = proof.public_values.read::<u32>();
    let b = proof.public_values.read::<u32>();

    println!("a: {}", a);
    println!("b: {}", b);

    // Verify proof and public values
    prover.verify(&proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!");
}
