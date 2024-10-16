use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("io-program");

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct MyPointUnaligned {
    pub x: usize,
    pub y: usize,
    pub b: bool,
}

fn main() {
    // Setup a tracer for logging.
    utils::setup_logger();

    // Create an input stream.
    let mut stdin = SP1Stdin::new();
    let p = MyPointUnaligned { x: 1, y: 2, b: true };
    let q = MyPointUnaligned { x: 3, y: 4, b: false };
    stdin.write(&p);
    stdin.write(&q);

    // Generate the proof for the given program.
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();

    // Read the output.
    let r = proof.public_values.read::<MyPointUnaligned>();
    println!("r: {:?}", r);

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        SP1ProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
