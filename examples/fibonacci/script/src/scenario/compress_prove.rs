use super::core_prove::mpc_prove_core;
use crate::{operator::operator_prepare_compress_inputs, ProveArgs};
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

    Ok(Vec::new())
}
