use super::compress_prove::mpc_prove_compress;
use crate::mmp::{
    common::{self, ProveArgs},
    operator::{operator_prove_plonk, operator_prove_shrink},
};
use crate::{PlonkBn254Proof, SP1Proof, SP1ProofWithPublicValues};
use anyhow::{Ok, Result};
use serde::{de::DeserializeOwned, Serialize};
use sp1_prover::SP1CoreProof;
use tracing::info_span;

pub fn mpc_prove_plonk<T: Serialize + DeserializeOwned>(
    args: &ProveArgs<T>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let span = info_span!("kroma_core");
    let _guard = span.entered();

    let (core_proof, compress_proof) = mpc_prove_compress(args).unwrap();
    let serialize_args = bincode::serialize(&args).unwrap();

    let mut shrink_proof = Vec::new();
    info_span!("o_shrink_proof").in_scope(|| {
        operator_prove_shrink::<T>(&serialize_args, &compress_proof, &mut shrink_proof)
    });

    let mut plonk_proof = Vec::new();
    info_span!("o_plonk_proof")
        .in_scope(|| operator_prove_plonk::<T>(&serialize_args, &shrink_proof, &mut plonk_proof));

    Ok((core_proof, compress_proof, plonk_proof))
}

pub fn scenario_end<T: Serialize + DeserializeOwned>(
    args: &ProveArgs<T>,
    core_proof: &Vec<u8>,
    plonk_proof: &Vec<u8>,
) -> Result<SP1ProofWithPublicValues> {
    let plonk_proof: PlonkBn254Proof = bincode::deserialize(plonk_proof).unwrap();

    let (client, _, _, vk) = common::init_client(args);
    let core_proof: SP1CoreProof = bincode::deserialize(&core_proof).unwrap();

    let proof = SP1ProofWithPublicValues {
        proof: SP1Proof::Plonk(plonk_proof),
        stdin: core_proof.stdin,
        public_values: core_proof.public_values,
        sp1_version: client.prover.version().to_string(),
    };

    client.verify(&proof, &vk).unwrap();
    tracing::info!("Successfully verified compress proof");

    Ok(proof)
}
