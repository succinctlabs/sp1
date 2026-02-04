use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("poseidon2-program");

#[tokio::main]
async fn main() {
    // Setup logging.
    sp1_sdk::utils::setup_logger();

    // The input stream that the program will read from using `sp1_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
    let stdin = SP1Stdin::new();

    // Create a `ProverClient` method.
    let client = ProverClient::from_env().await;

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    
    let (_, report) = client.execute(ELF, stdin.clone()).await.unwrap();
    println!("executed program {:?} ", report);
 

    // Generate the proof for the given program and input.
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin.clone()).core().await.unwrap();
    println!("generated proof");
    
    // Verify proof and public values
    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
    println!("verified proof");
    
}
