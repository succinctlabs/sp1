use super::compress_prove::mpc_prove_compress;
use crate::{
    common,
    operator::{operator_prove_plonk, operator_prove_shrink},
    ProveArgs,
};
use anyhow::Result;
use sp1_prover::SP1CoreProof;
use sp1_sdk::{PlonkBn254Proof, SP1Proof, SP1ProofWithPublicValues};

pub fn mpc_prove_plonk(args: ProveArgs) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (core_proof, compress_proof) = mpc_prove_compress(args.clone()).unwrap();
    let serialize_args = bincode::serialize(&args).unwrap();

    let mut shrink_proof = Vec::new();
    operator_prove_shrink(&serialize_args, &compress_proof, &mut shrink_proof);

    let mut plonk_proof = Vec::new();
    operator_prove_plonk(&serialize_args, &shrink_proof, &mut plonk_proof);

    Ok((core_proof, compress_proof, plonk_proof))
}

pub fn scenario_end(args: ProveArgs, core_proof: &Vec<u8>, plonk_proof: &Vec<u8>) {
    let plonk_proof: PlonkBn254Proof = bincode::deserialize(plonk_proof).unwrap();

    let (client, _, _, vk) = common::init_client(args.clone());
    let core_proof: SP1CoreProof = bincode::deserialize(&core_proof).unwrap();

    let proof = SP1ProofWithPublicValues {
        proof: SP1Proof::Plonk(plonk_proof),
        stdin: core_proof.stdin,
        public_values: core_proof.public_values,
        sp1_version: client.prover.version().to_string(),
    };

    client.verify(&proof, &vk).unwrap();
    tracing::info!("Successfully verified compress proof");
}
