use super::core_prove::mpc_prove_core;
use crate::{
    operator::operator_prepare_compress_inputs, worker::worker_compress_proofs, ProveArgs,
};
use anyhow::Result;

pub fn mpc_prove_compress(args: ProveArgs) -> Result<Vec<u8>> {
    let core_proof = mpc_prove_core(args.clone()).unwrap();

    let serialize_args = bincode::serialize(&args).unwrap();
    let mut rec_layouts: Vec<Vec<u8>> = Vec::new();
    let mut def_layouts: Vec<Vec<u8>> = Vec::new();
    let mut last_proof_public_values = Vec::new();
    operator_prepare_compress_inputs(
        &serialize_args,
        &core_proof,
        &mut rec_layouts,
        &mut def_layouts,
        &mut last_proof_public_values,
    );

    let mut compressed_proofs = Vec::new();
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

    Ok(Vec::new())
}
