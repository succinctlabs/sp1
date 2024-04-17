use std::time::Duration;
use tokio::runtime::Runtime;

use reqwest::Client;
use sp1_sdk::{utils, ProverClient, PublicValues, SP1Stdin};

use sha2::{Digest, Sha256};
use tendermint_light_client_verifier::options::Options;
use tendermint_light_client_verifier::types::LightBlock;
use tendermint_light_client_verifier::ProdVerifier;
use tendermint_light_client_verifier::Verdict;
use tendermint_light_client_verifier::Verifier;

use crate::util::{fetch_latest_commit, fetch_light_block, verify_blocks};

const TENDERMINT_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");
mod util;

async fn get_light_blocks(rpc_url: &str) -> (LightBlock, LightBlock) {
    // Uniquely identify a peer in the network.
    let peer_id: [u8; 20] = [
        0x72, 0x6b, 0xc8, 0xd2, 0x60, 0x38, 0x7c, 0xf5, 0x6e, 0xcf, 0xad, 0x3a, 0x6b, 0xf6, 0xfe,
        0xcd, 0x90, 0x3e, 0x18, 0xa2,
    ];
    let client = Client::new();
    let url = format!("{}/commit", rpc_url);
    let latest_commit = fetch_latest_commit(&client, &url).await.unwrap();
    let block: u64 = latest_commit.result.signed_header.header.height.into();
    println!("Latest block: {}", block);
    let light_block_1 = fetch_light_block(block - 20, peer_id, BASE_URL)
        .await
        .expect("Failed to generate light block 1");
    let light_block_2 = fetch_light_block(block, peer_id, BASE_URL)
        .await
        .expect("Failed to generate light block 2");
    (light_block_1, light_block_2)
}

fn main() {
    // Setup the logger.
    utils::setup_logger();

    // Right now, we will use the Celestia mocha testnet.
    const BASE_URL: &str = "https://celestia-mocha-rpc.publicnode.com:443";

    // Our zkVM program uses as input 
    let rt = Runtime::new().unwrap();
    let (light_block_1, light_block_2) = rt.block_on(async { get_light_blocks(BASE_URL).await });


    // We create a `SP1Stdin`` object that will be used during proving to provide the inputs to
    // our program.
    let mut stdin = SP1Stdin::new();
    
    // Serialize the blocks to a a vector of bytes.
    let encoded_1 = serde_cbor::to_vec(&light_block_1).unwrap();
    let encoded_2 = serde_cbor::to_vec(&light_block_2).unwrap();

    // Write the encoded blocks to the stdin.
    stdin.write_vec(encoded_1);
    stdin.write_vec(encoded_2);

    // Instantiate a `ProverClient` that can be used for proving and verifying. 
    let prover = Prover::new();

    // To generate a proof, we provide the program (the ELF is the "bytecode" of our program) and
    // also the `stdin` which contains the inputs for the program. Note that by default
    // the `ProverClient` when run locally will run the program and generate a mock proof. This
    // is helpful for debugging program execution and also determining the approximate cycle count
    // and cost of proving. When the environment variable `SUCCINCT_NETWORK_RPC` is set
    // and `REMOTE_PROVE=true`, then the `ProverClient` will automatically send the proof for 
    // generation to the Succinct Network. If you wish to generate proofs locally, then you can
    // set the `LOCAL_PROVE=true` environment variable. By default this will generate a larger STARK
    // proof.
    let proof = prover.prove(TENDERMINT_ELF, stdin).expect("proving failed");

    // Verify proof.
    prover
        .verify(TENDERMINT_ELF, &proof)
        .expect("verification failed");

    // The proof will come with a `PublicValues` field that contains the public values that were
    // written to by the program. You can read it as follows:

    let public_values = proof.public_values();

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}

