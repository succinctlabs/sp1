use sp1_sdk::{utils, ProverClient, SP1Stdin};

const UINT256_ARITHMETIC_ELF: &[u8] =
    include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
    utils::setup_logger();
    let stdin = SP1Stdin::new();

    let client = ProverClient::new();
    let (pk, vk) = client.setup(UINT256_ARITHMETIC_ELF);
    let proof = client.prove(&pk, stdin).expect("proving failed");

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
