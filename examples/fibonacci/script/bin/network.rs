use sp1_sdk::{
    include_elf,
    network_v2::{
        prover::NetworkProver,
        proto::network::FulfillmentStrategy,
        Error,
    },
    utils,
    SP1Stdin,
    Prover
};
use std::env;
use tokio;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci-program");

#[tokio::main]
async fn main() {
    // Setup logging.
    utils::setup_logger();

    // Create the prover.
    let private_key = env::var("SP1_PRIVATE_KEY").expect("PRIVATE_KEY must be set");
    let prover = NetworkProver::new(&private_key, None, false)
        .with_cycle_limit(20_000) // Set manual cycle limit
        .with_timeout_secs(3600) // 1 hour timeout
        .with_strategy(FulfillmentStrategy::Hosted) // Use hosted strategy
        .skip_simulation(); // Skip simulation since we know our cycle requirements

    // Setup proving key and verifying key.
    let (pk, vk) = prover.setup(ELF);

    // The input stream that the program will read from using `sp1_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
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
