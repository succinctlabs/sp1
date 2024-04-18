use sp1_sdk::{utils, ProverClient, SP1Stdin};

const ED25519_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup logger.
    utils::setup_logger();

    // Generate proof.
    let client = ProverClient::new();
    let stdin = SP1Stdin::new();
    let proof = client.prove(ED25519_ELF, stdin).expect("proving failed");

    // Verify proof.
    client
        .verify(ED25519_ELF, &proof)
        .expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
