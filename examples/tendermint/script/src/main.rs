use reqwest::Client;
use sp1_sdk::utils::{setup_logger, BabyBearPoseidon2};
use sp1_sdk::{SP1Prover, SP1Stdin, SP1Verifier};

use crate::util::fetch_latest_commit;
use crate::util::fetch_light_block;

const TENDERMINT_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");
mod util;

#[tokio::main]
async fn main() {
    // Generate proof.
    setup_logger();
    // Uniquely identify a peer in the network.
    let peer_id: [u8; 20] = [
        0x72, 0x6b, 0xc8, 0xd2, 0x60, 0x38, 0x7c, 0xf5, 0x6e, 0xcf, 0xad, 0x3a, 0x6b, 0xf6, 0xfe,
        0xcd, 0x90, 0x3e, 0x18, 0xa2,
    ];
    const BASE_URL: &str = "https://celestia-mocha-rpc.publicnode.com:443";
    let client = Client::new();
    let url = format!("{}/commit", BASE_URL);
    let latest_commit = fetch_latest_commit(&client, &url).await.unwrap();
    let block: u64 = latest_commit.result.signed_header.header.height.into();
    println!("Latest block: {}", block);

    let light_block_1 = fetch_light_block(block - 20, peer_id, BASE_URL)
        .await
        .expect("Failed to generate light block 1");

    let light_block_2 = fetch_light_block(block, peer_id, BASE_URL)
        .await
        .expect("Failed to generate light block 2");
    let mut stdin = SP1Stdin::new();

    let encoded_1 = serde_cbor::to_vec(&light_block_1).unwrap();
    let encoded_2 = serde_cbor::to_vec(&light_block_2).unwrap();

    stdin.write(&encoded_1);
    stdin.write(&encoded_2);

    let mut proof = SP1Prover::prove(TENDERMINT_ELF, stdin).expect("proving failed");

    // Verify proof.
    SP1Verifier::verify(TENDERMINT_ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
