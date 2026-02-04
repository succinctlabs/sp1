use sp1_sdk::{include_elf, utils, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("fibonacci-program");

#[tokio::main]
async fn main() {
    // Setup logging.
    utils::setup_logger();

    // Create an input stream and write '500' to it.
    let n = 500u32;
    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    // Generate the constant-sized proof for the given program and input.
    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    let mut proof = client.prove(&pk, stdin).compressed().await.unwrap();

    println!("generated proof");
    // Read and verify the output.
    let _ = proof.public_values.read::<u32>();
    let a = proof.public_values.read::<u32>();
    let b = proof.public_values.read::<u32>();
    println!("a: {}, b: {}", a, b);

    // Verify proof and public values
    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");

    // Save the proof.
    proof.save("compressed-proof-with-pis.bin").expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
