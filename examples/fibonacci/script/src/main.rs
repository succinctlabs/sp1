use sp1_sdk::{utils, SP1Prover, SP1Stdin, SP1Verifier, client::NetworkClient};
use sp1_sdk::utils::BabyBearPoseidon2;
use std::env;
use tokio::time::Duration;
use tokio::time::sleep;
use sp1_sdk::proto::network::ProofStatus;
use sp1_sdk::SP1ProofWithIO;
use sp1_sdk::client::StarkGenericConfig;
use serde::{Deserialize, Serialize};

use log::info;
use anyhow::Result;
/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

async fn poll_proof<SC: for<'de> Deserialize<'de> + Serialize + StarkGenericConfig>(
    network_client: NetworkClient,
    proof_id: &str,
) -> Result<SP1ProofWithIO<SC>> {
    // Query every 10 seconds for the proof status.
    // TODO: Proof status should be an object (instead of a tuple).
    // TODO: THe STARK config is annoying.

    const POLL_INTERVAL: u64 = 10;
    const MAX_NUM_POLLS: u64 = 1000;

    for _ in 0..MAX_NUM_POLLS {
        info!("Polling proof status");
        let proof_status = network_client.get_proof_status::<SC>(proof_id).await;
        if let Ok(proof_status) = proof_status {
            info!("Proof status: {:?}", proof_status.0.status());
            if proof_status.0.status() == ProofStatus::ProofSucceeded {
                if let Some(proof_data) = proof_status.1 {
                    return Ok(proof_data);
                }
            }
        }
        sleep(Duration::from_secs(POLL_INTERVAL)).await;
    }

    Err(anyhow::anyhow!("Proof failed or was rejected"))
}

#[tokio::main]
async fn main() {
    // Setup a tracer for logging.
    dotenv::dotenv().ok();
    utils::setup_logger();

    let network_client = NetworkClient::with_token(
        env::var("SP1_NETWORK_TOKEN").expect("SP1_NETWORK_TOKEN not set"),
    );

    let proof_id = network_client
        .create_proof(ELF, &[]).await;

    info!("proof_id: {:?}", proof_id);

    if let Ok(proof_id) = proof_id {
        type SC = BabyBearPoseidon2;
        let proof = poll_proof::<SC>(network_client, &proof_id).await;
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
