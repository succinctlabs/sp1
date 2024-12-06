use sp1_sdk::network_v2::prover::NetworkProver;
use sp1_sdk::Prover;
use sp1_sdk::SP1Stdin;
use sp1_sdk::{
    include_elf,
    network_v2::{proto::network::FulfillmentStrategy, Error},
    utils, ProverClient,
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

    let proof_result = prover.prove(&pk, stdin).await;
    let mut proof = match proof_result {
        Ok(proof) => proof,
        Err(e) => match e {
            Error::SimulationFailed => {
                eprintln!("Failed to simulate program execution. Try setting a manual cycle limit with skip_simulation()");
                std::process::exit(1);
            }
            Error::RequestTimedOut => {
                eprintln!("Proof generation timed out. Try increasing the timeout duration");
                std::process::exit(1);
            }
            Error::RequestUnexecutable => {
                eprintln!("Program is not executable. Check your input parameters");
                std::process::exit(1);
            }
            Error::RequestUnfulfillable => {
                eprintln!("No prover available to fulfill the request. Try again later");
                std::process::exit(1);
            }
            Error::RegistrationFailed => {
                eprintln!("Failed to register program with the network");
                std::process::exit(1);
            }
            Error::NetworkError(status) => {
                eprintln!("Network communication error: {}", status);
                std::process::exit(1);
            }
            Error::Other(e) => {
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
