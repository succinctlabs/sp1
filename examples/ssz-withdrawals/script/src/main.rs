use sp1_sdk::{utils, ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
    // utils::setup_tracer();
    utils::setup_logger();

    let stdin = SP1Stdin::new();
    let client = ProverClient::new();
    let proof = client.prove(ELF, stdin).expect("proving failed");

    // Verify proof.
    client.verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
