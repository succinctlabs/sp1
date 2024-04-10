use serde::{Deserialize, Serialize};
use sp1_sdk::client::StarkGenericConfig;
use sp1_sdk::proto::network::ProofStatus;
use sp1_sdk::utils::BabyBearPoseidon2;
use sp1_sdk::SP1ProofWithIO;
use sp1_sdk::{client::NetworkClient, utils, SP1Prover, SP1Stdin, SP1Verifier};
use std::env;
use tokio::time::sleep;
use tokio::time::Duration;

use anyhow::Result;
use log::info;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[tokio::main]
async fn main() {
    // Setup a tracer for logging.
    dotenv::dotenv().ok();
    utils::setup_logger();

    let network_client = NetworkClient::with_token(
        env::var("SP1_NETWORK_TOKEN").expect("SP1_NETWORK_TOKEN not set"),
    );

    let proof_id = network_client.create_proof(ELF, &[]).await;

    info!("proof_id: {:?}", proof_id);

    if let Ok(proof_id) = proof_id {
        type SC = BabyBearPoseidon2;
        let proof = network_client.poll_proof::<SC>(&proof_id, 1000, 10).await;
        if let Ok(valid_proof) = proof {
            info!("Proof: {:?}", valid_proof.public_values.buffer.data);
        }
    }

    // // Create an input stream.
    // let stdin = SP1Stdin::new();

    // // Generate the proof for the given program.
    // let proof = SP1Prover::prove(ELF, stdin).expect("proving failed");

    // // Verify proof.
    // SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // // Save the proof.
    // proof
    //     .save("proof-with-pis.json")
    //     .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
