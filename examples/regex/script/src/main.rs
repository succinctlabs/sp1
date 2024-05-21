use sp1_sdk::{utils, ProverClient, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const REGEX_IO_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup a tracer for logging.
    utils::setup_logger();

    // Create a new stdin with d the input for the program.
    let mut stdin = SP1Stdin::new();

    let pattern = "a+".to_string();
    let target_string = "an era of truth, not trust".to_string();

    // Write in a simple regex pattern.
    stdin.write(&pattern);
    stdin.write(&target_string);

    // Generate the proof for the given program and input.
    let client = ProverClient::new();
    let (pk, vk) = client.setup(REGEX_IO_ELF);
    let mut proof = client.prove(&pk, stdin).expect("proving failed");

    // Read the output.
    let res = proof.public_values.read::<bool>();
    println!("res: {}", res);

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Save the proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
