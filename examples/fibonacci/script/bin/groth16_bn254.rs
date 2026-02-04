use sp1_sdk::{
    include_elf, utils, Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin,
};

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

    // Set up the pk and vk.
    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();
    println!("vk: {:?}", pk.verifying_key().bytes32());

    // Generate the Groth16 proof.
    let proof = client.prove(&pk, stdin).groth16().await.unwrap();
    println!("generated proof");

    // Get the public values as bytes.
    let public_values = proof.public_values.as_slice();
    println!("public values: 0x{}", hex::encode(public_values));

    // Get the proof as bytes.
    let solidity_proof = proof.bytes();
    println!("proof: 0x{}", hex::encode(solidity_proof));

    // Verify proof and public values
    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");

    // Save the proof.
    proof.save("fibonacci-groth16.bin").expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
