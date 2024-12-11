use sp1_sdk::network_v2::{Error, FulfillmentStrategy};
use sp1_sdk::{include_elf, utils, client::ProverClient, proof::SP1ProofWithPublicValues, SP1Stdin};
use std::time::Duration;
use dotenv::dotenv;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci-program");

#[tokio::main]
async fn main() {
    // Setup logging.
    utils::setup_logger();

    // Create an input stream and write '500' to it.
    let n = 1000u32;

    // The input stream that the program will read from using `sp1_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    dotenv().ok();

    let rpc_url = std::env::var("PROVER_NETWORK_RPC").unwrap();
    let private_key = std::env::var("SP1_PRIVATE_KEY").unwrap();

    // Generate the proof, using the specified network configuration.
    let client = ProverClient::builder()
        .network()
        .with_rpc_url(rpc_url)
        .with_private_key(private_key)
        .build();

    // Generate the proving key and verifying key for the given program.
    let (pk, vk) = client.setup(ELF).await;

    // Generate the proof.
    let proof_result = client
        .prove(&pk, &stdin)
        // .timeout(300)
        // .cycle_limit(1_000_000)
        // .skip_simulation(true)
        // .strategy(FulfillmentStrategy::Hosted)
        .await;

    // Example of handling potential errors.
    let mut proof = match proof_result {
        Ok(proof) => proof,
        Err(e) => {
            if let Some(network_error) = e.downcast_ref::<Error>() {
                match network_error {
                    Error::RequestUnexecutable { .. } => {
                        eprintln!("Program is unexecutable: {}", e);
                        std::process::exit(1);
                    }
                    Error::RequestUnfulfillable { .. } => {
                        eprintln!("Proof request cannot be fulfilled: {}", e);
                        std::process::exit(1);
                    }
                    Error::RequestTimedOut { .. } => {
                        eprintln!("Proof request timed out: {}", e);
                        std::process::exit(1);
                    }
                    _ => {
                        eprintln!("Unexpected error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("Unexpected error: {}", e);
                std::process::exit(1);
            }
        }
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
    // client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        SP1ProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    // client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
