use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("fibonacci-cuda-program");

#[tokio::main]
async fn main() {
    // Setup logging.
    sp1_sdk::utils::setup_logger();

    // Create an input stream and write '500' to it.
    let n = 1000u32;

    // The input stream that the program will read from using `sp1_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    // Create a `ProverClient` method.
    let client = ProverClient::builder().cuda().build().await;
    let client2 = ProverClient::builder().cuda().build().await;

    let handle = tokio::spawn({
        let stdin = stdin.clone();
        async move {
            let pk = client2.setup(ELF).await.unwrap();
            let proof = client2.prove(&pk, stdin.clone()).compressed().await.unwrap();
            client2.verify(&proof, &pk.verifying_key(), None).unwrap();
        }
    });

    // Generate the proof for the given program and input.
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin.clone()).compressed().await.unwrap();
    client.verify(&proof, &pk.verifying_key(), None).unwrap();
    
    handle.await.unwrap();

    println!("generated and verified proofs");
}
