//! A simple example showing how to aggregate proofs of multiple programs with SP1.

use sp1_sdk::{prelude::*, SP1VerifyingKey};
use sp1_sdk::{ProverClient, SP1Proof};
use tracing::Instrument;

/// A program that aggregates the proofs of the simple program.
const AGGREGATION_ELF: Elf = include_elf!("aggregation-program");

/// A program that just runs a simple computation.
const FIBONACCI_ELF: Elf = include_elf!("fibonacci-program");

/// An input to the aggregation program.
///
/// Consists of a proof and a verification key.
struct AggregationInput {
    pub proof: SP1ProofWithPublicValues,
    pub vk: SP1VerifyingKey,
}

#[tokio::main]
async fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::from_env().await;

    // Setup the proving and verifying keys.
    let pk = client.setup(FIBONACCI_ELF).await.unwrap();

    let proof_1 = async {
        let mut stdin = SP1Stdin::new();
        stdin.write(&10);
        client.prove(&pk, stdin.clone()).compressed().await.unwrap()
    }
    .instrument(tracing::info_span!("generate fibonacci proof n=10"))
    .await;

    let proof_2 = async {
        let mut stdin = SP1Stdin::new();
        stdin.write(&20);
        client.prove(&pk, stdin.clone()).compressed().await.unwrap()
    }
    .instrument(tracing::info_span!("generate fibonacci proof n=20"))
    .await;

    let proof_3 = async {
        let mut stdin = SP1Stdin::new();
        stdin.write(&30);
        client.prove(&pk, stdin.clone()).compressed().await.unwrap()
    }
    .instrument(tracing::info_span!("generate fibonacci proof n=30"))
    .await;

    // Setup the inputs to the aggregation program.
    let input_1 = AggregationInput { proof: proof_1, vk: pk.verifying_key().clone() };
    let input_2 = AggregationInput { proof: proof_2, vk: pk.verifying_key().clone() };
    let input_3 = AggregationInput { proof: proof_3, vk: pk.verifying_key().clone() };
    let inputs = vec![input_1, input_2, input_3];

    // Aggregate the proofs.
    let agg_pk = client.setup(AGGREGATION_ELF).await.unwrap();
    async {
        let mut stdin = SP1Stdin::new();

        // Write the verification keys.
        let vkeys = inputs.iter().map(|input| input.vk.hash_u32()).collect::<Vec<_>>();
        stdin.write::<Vec<[u32; 8]>>(&vkeys);

        // Write the public values.
        let public_values =
            inputs.iter().map(|input| input.proof.public_values.to_vec()).collect::<Vec<_>>();
        stdin.write::<Vec<Vec<u8>>>(&public_values);

        // Write the proofs.
        //
        // Note: this data will not actually be read by the aggregation program, instead it will be
        // witnessed by the prover during the recursive aggregation process inside SP1 itself.
        for input in inputs {
            let SP1Proof::Compressed(proof) = input.proof.proof else { panic!() };
            stdin.write_proof(*proof, input.vk.vk);
        }

        // Generate the plonk bn254 proof.
        client.prove(&agg_pk, stdin).plonk().await.expect("proving failed");
    }
    .instrument(tracing::info_span!("aggregate the proofs"))
    .await;
}
