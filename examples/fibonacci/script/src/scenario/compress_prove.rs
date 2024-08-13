use super::core_prove::mpc_prove_core;
use crate::{
    common,
    operator::{operator_prepare_compress_input_chunks, operator_prepare_compress_inputs},
    scenario,
    worker::worker_compress_proofs,
    ProveArgs,
};
use anyhow::Result;
use sp1_core::{stark::ShardProof, utils::BabyBearPoseidon2};
use sp1_prover::SP1ReduceProof;
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};
use tracing::info_span;

pub fn mpc_prove_compress(args: ProveArgs) -> Result<(Vec<u8>, Vec<u8>)> {
    let span = info_span!("kroma_core");
    let _guard = span.entered();

    let core_proof = mpc_prove_core(args.clone()).unwrap();
    let serialize_args = bincode::serialize(&args).unwrap();

    let mut rec_layouts: Vec<Vec<u8>> = Vec::new();
    let mut def_layouts: Vec<Vec<u8>> = Vec::new();
    let mut last_proof_public_values = Vec::new();
    info_span!("o_prepare_compress_inputs").in_scope(|| {
        operator_prepare_compress_inputs(
            &serialize_args,
            &core_proof,
            &mut rec_layouts,
            &mut def_layouts,
            &mut last_proof_public_values,
        )
    });

    let mut compressed_proofs = Vec::new();
    info_span!("w_compress_proofs_leaf").in_scope(|| {
        for layout in rec_layouts {
            let mut compressed_proof = Vec::new();
            worker_compress_proofs(
                &serialize_args,
                &layout,
                0,
                Some(&last_proof_public_values),
                &mut compressed_proof,
            );
            compressed_proofs.push(compressed_proof);
        }
        for layout in def_layouts {
            let mut compressed_proof = Vec::new();
            worker_compress_proofs(&serialize_args, &layout, 1, None, &mut compressed_proof);
            compressed_proofs.push(compressed_proof);
        }
    });

    let mut compress_layer_proofs = compressed_proofs;
    let compressed_proof = loop {
        // Operator
        let mut red_layout = Vec::new();
        info_span!("o_prepare_compress_input_chunks").in_scope(|| {
            operator_prepare_compress_input_chunks(&compress_layer_proofs, &mut red_layout)
        });

        // Worker
        compress_layer_proofs = Vec::new();
        info_span!("w_compress_proofs").in_scope(|| {
            for (worker_idx, layout) in red_layout.iter().enumerate() {
                let mut compressed_proof = Vec::new();
                worker_compress_proofs(&serialize_args, &layout, 2, None, &mut compressed_proof);
                compress_layer_proofs.push(compressed_proof);
                tracing::info!("{:?}/{:?} worker done", worker_idx + 1, red_layout.len());
            }
        });
        if compress_layer_proofs.len() == 1 {
            break compress_layer_proofs.remove(0);
        }
    };

    let shard_proof: ShardProof<BabyBearPoseidon2> =
        bincode::deserialize(&compressed_proof).unwrap();
    let proof = SP1ReduceProof { proof: shard_proof };
    let proof = bincode::serialize(&proof).unwrap();
    tracing::info!("proof size: {:?}", proof.len());

    Ok((core_proof, proof))
}

pub fn scenario_end(args: ProveArgs, core_proof: &Vec<u8>, compress_proof: &Vec<u8>) {
    let compress_proof_obj: SP1ReduceProof<BabyBearPoseidon2> =
        bincode::deserialize(compress_proof).unwrap();

    let (client, _, _, vk) = common::init_client(args.clone());
    let core_proof = scenario::core_prove::scenario_end(args, &core_proof).unwrap();

    let proof = SP1ProofWithPublicValues {
        proof: SP1Proof::Compressed(compress_proof_obj.proof),
        stdin: core_proof.stdin,
        public_values: core_proof.public_values,
        sp1_version: client.prover.version().to_string(),
    };

    client.verify(&proof, &vk).unwrap();
    tracing::info!("Successfully verified compress proof");
}
