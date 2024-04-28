use sp1_sdk::{utils, ProverClient, SP1Stdin};

const TENDERMINT_BENCHMARK_ELF: &[u8] =
    include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup logger.
    utils::setup_logger();

    // Generate proof.
    let client = ProverClient::new();
    let stdin = SP1Stdin::new();
    let (pk, vk) = client.setup(TENDERMINT_BENCHMARK_ELF);
    let proof = client.prove(&pk, stdin).expect("proving failed");

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
