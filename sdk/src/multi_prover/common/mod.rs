pub mod memory_layouts;
pub mod types;

use crate::{ProverClient, SP1ProofKind};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sp1_core::{
    runtime::{Program, Runtime, SP1Context, SP1ContextBuilder},
    utils::SP1ProverOpts,
};
use sp1_prover::{
    types::{SP1ProvingKey, SP1VerifyingKey},
    SP1Stdin,
};
use std::sync::Arc;
use sysinfo::System;

static LIMIT_RAM_GB: u64 = 120;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProveArgs {
    pub zkvm_input: Vec<u8>,
    pub elf: Vec<u8>,
}

impl ProveArgs {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_slice(args: &[u8]) -> Self {
        bincode::deserialize(args).unwrap()
    }
}

pub fn init_client(args: &ProveArgs) -> (ProverClient, SP1Stdin, SP1ProvingKey, SP1VerifyingKey) {
    let client = ProverClient::new();
    let (pk, vk) = client.setup(&args.elf);
    let mut stdin = SP1Stdin::new();
    stdin.write(&args.zkvm_input);

    (client, stdin, pk, vk)
}

pub fn bootstrap<'a>(
    client: &'a ProverClient,
    pk: &SP1ProvingKey,
) -> Result<(Program, SP1ProverOpts, SP1Context<'a>)> {
    // TODO(Ethan): remove `kind` since it is not used.
    let kind = SP1ProofKind::default();
    let opts = SP1ProverOpts::default();

    let mut context_builder = SP1ContextBuilder::default();
    let mut context = context_builder.build();

    // prove function in local.rs
    // Operator only.
    let total_ram_gb = System::new_all().total_memory() / 1_000_000_000;
    if kind == SP1ProofKind::Plonk && total_ram_gb <= LIMIT_RAM_GB {
        return Err(anyhow::anyhow!(
            "not enough memory to generate plonk proof. at least 128GB is required."
        ));
    };

    context
        .subproof_verifier
        .get_or_insert_with(|| Arc::new(client.prover.sp1_prover()));

    let program = Program::from(pk.elf.as_slice());

    Ok((program, opts, context))
}

pub fn build_runtime<'a>(
    program: Program,
    stdin: &SP1Stdin,
    opts: SP1ProverOpts,
    context: SP1Context<'a>,
) -> Runtime<'a> {
    let mut runtime = Runtime::with_context(program, opts.core_opts, context);
    runtime.write_vecs(&stdin.buffer);
    for proof in stdin.proofs.iter() {
        runtime.write_proof(proof.0.clone(), proof.1.clone());
    }
    runtime
}
