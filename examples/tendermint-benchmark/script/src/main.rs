use sp1_sdk::{utils, ProverClient, SP1Stdin};

const ED25519_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
    utils::setup_logger();
    let stdin = SP1Stdin::new();
    let client = ProverClient::new();
    let proof = client::prove(ED25519_ELF, stdin).expect("proving failed");

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
