use sp1_core::{utils, SP1Prover, SP1Stdin, SP1Verifier};

use crate::util::fetch_light_block;

const TENDERMINT_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");
mod util;

#[tokio::main]
async fn main() {
    // Generate proof.
    utils::setup_logger();
    // Uniquely identify a peer in the network.
    let peer_id: [u8; 20] = [
        0x72, 0x6b, 0xc8, 0xd2, 0x60, 0x38, 0x7c, 0xf5, 0x6e, 0xcf, 0xad, 0x3a, 0x6b, 0xf6, 0xfe,
        0xcd, 0x90, 0x3e, 0x18, 0xa2,
    ];
    let light_block_1 = fetch_light_block(10000, peer_id)
        .await
        .expect("Failed to generate light block 1");

    let light_block_2 = fetch_light_block(10020, peer_id)
        .await
        .expect("Failed to generate light block 2");
    let mut stdin = SP1Stdin::new();

    stdin.write(&light_block_1);
    stdin.write(&light_block_2);

    let proof = SP1Prover::prove(TENDERMINT_ELF, stdin).expect("proving failed");

    // Verify proof.
    SP1Verifier::verify(TENDERMINT_ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
