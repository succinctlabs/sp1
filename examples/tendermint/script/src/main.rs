use reqwest::Client;
use sp1_sdk::{utils, SP1Prover, SP1Stdin, SP1Verifier};

use sha2::{Digest, Sha256};
use tendermint_light_client_verifier::Verdict;

use crate::util::fetch_latest_commit;
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

    // TODO: normally we could just write the LightBlock, but bincode doesn't work with LightBlock.
    // The following code will panic.
    // let encoded: Vec<u8> = bincode::serialize(&light_block_1).unwrap();
    // let decoded: LightBlock = bincode::deserialize(&encoded[..]).unwrap();

    let mut proof = SP1Prover::prove(TENDERMINT_ELF, stdin).expect("proving failed");

    // Verify proof.
    SP1Verifier::verify(TENDERMINT_ELF, &proof).expect("verification failed");

    // Read the output.
    let verdict = proof.stdout.read::<Verdict>();
    let verdict_encoded = serde_cbor::to_vec(&verdict).unwrap();

    // Verify the public inputs
    let mut pi_hasher = Sha256::new();
    pi_hasher.update(light_block_1.signed_header.header.hash());
    pi_hasher.update(light_block_2.signed_header.header.hash());
    pi_hasher.update(&verdict_encoded);
    let pi_digest: &[u8] = &pi_hasher.finalize();

    let proof_pi_bytes: Vec<u8> = proof.proof.pi_digest.into();
    assert_eq!(proof_pi_bytes.as_slice(), pi_digest);

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
