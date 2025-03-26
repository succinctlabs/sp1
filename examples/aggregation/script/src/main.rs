//! A simple example showing how to aggregate proofs of multiple programs with SP1.

use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin,
    SP1VerifyingKey,
};

/// A program that aggregates the proofs of the simple program.
const AGGREGATION_ELF: &[u8] = include_elf!("aggregation-program");

/// A program that just runs a simple computation.
const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

/// An input to the aggregation program.
///
/// Consists of a proof and a verification key.
struct AggregationInput {
    pub proof: SP1ProofWithPublicValues,
    pub vk: SP1VerifyingKey,
}

// A function to generate the Fibonacci proof for a given number
fn generate_fibonacci_proof(client: &ProverClient, pk: &HashableKey, n: u32) -> SP1ProofWithPublicValues {
    let mut stdin = SP1Stdin::new();
    stdin.write(&n);
    client.prove(pk, &stdin).compressed().run().expect("proving failed")
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::from_env();

    // Setup the proving and verifying keys.
    let (fibonacci_pk, fibonacci_vk) = client.setup(FIBONACCI_ELF);

    // Using the function to generate proofs for Fibonacci numbers
    let ns = [10, 20, 30];
    let inputs: Vec<AggregationInput> = ns.iter().map(|&n| {
        let proof = generate_fibonacci_proof(&client, &fibonacci_pk, n);
        AggregationInput { proof, vk: fibonacci_vk.clone() }
    }).collect();

    // Setup the inputs to the aggregation program.
    let (aggregation_pk, _) = client.setup(AGGREGATION_ELF);

    // Aggregate the proofs.
    tracing::info_span!("aggregate the proofs").in_scope(|| {
        let mut stdin = SP1Stdin::new();

        // Write the verification keys.
        let vkeys = inputs.iter().map(|input| input.vk.hash_u32()).collect::<Vec<_>>();
        stdin.write(&vkeys);

        // Write the public values.
        let public_values = inputs.iter().map(|input| input.proof.public_values.to_vec()).collect::<Vec<_>>();
        stdin.write(&public_values);

        // Write the proofs.
        //
        // Note: this data will not actually be read by the aggregation program, instead it will be
        // witnessed by the prover during the recursive aggregation process inside SP1 itself.
        for input in inputs {
            let SP1Proof::Compressed(proof) = input.proof.proof else { panic!("Invalid proof type") };
            stdin.write_proof(*proof, input.vk.vk);
        }

        // Generate the plonk bn254 proof.
        client.prove(&aggregation_pk, &stdin).plonk().run().expect("proving failed");
    });
}
