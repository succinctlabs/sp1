use once_cell::sync::Lazy;
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

static CLIENT: Lazy<ProverClient> = Lazy::new(|| ProverClient::from_env());

fn generate_fibonacci_proof(fibonacci_pk: &SP1ProvingKey, n: u32) -> Result<SP1ProofWithPublicValues, Box<dyn std::error::Error>> {
    tracing::info_span!("generate fibonacci proof", n = n).in_scope(|| {
        let mut stdin = SP1Stdin::new();
        stdin.write(&n);
        Ok(CLIENT.prove(fibonacci_pk, &stdin).compressed().run()?)
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Setup the proving and verifying keys.
    let (aggregation_pk, _) = CLIENT.setup(AGGREGATION_ELF)?;
    let (fibonacci_pk, fibonacci_vk) = CLIENT.setup(FIBONACCI_ELF)?;

    // Generate the fibonacci proofs.
    let inputs = vec![10, 20, 30]
        .into_iter()
        .map(|n| {
            let proof = generate_fibonacci_proof(&fibonacci_pk, n)?;
            Ok(AggregationInput {
                proof,
                vk: fibonacci_vk.clone(),
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;

    // Aggregate the proofs.
    tracing::info_span!("aggregate the proofs").in_scope(|| {
        let mut stdin = SP1Stdin::new();

        // Write the verification keys.
        let vkeys = inputs.iter().map(|input| input.vk.hash_u32()).collect::<Vec<_>>();
        stdin.write::<Vec<[u32; 8]>>(&vkeys);

        // Write the public values.
        let public_values = inputs.iter().map(|input| input.proof.public_values.to_vec()).collect::<Vec<_>>();
        stdin.write::<Vec<Vec<u8>>>(&public_values);

        // Write the proofs.
        for input in inputs {
            let SP1Proof::Compressed(proof) = input.proof.proof else { panic!() };
            stdin.write_proof(*proof, input.vk.vk);
        }

        // Generate the plonk bn254 proof.
        CLIENT.prove(&aggregation_pk, &stdin).plonk().run()?;
        Ok(())
    })?;

    Ok(())
}
