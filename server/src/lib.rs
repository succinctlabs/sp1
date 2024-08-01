#[rustfmt::skip]
pub mod proto {
    pub mod api;
}

use serde::{Deserialize, Serialize};
use sp1_core::io::SP1Stdin;
use sp1_core::stark::ShardProof;
use sp1_core::utils::SP1ProverOpts;
use sp1_prover::types::SP1ProvingKey;
use sp1_prover::InnerSC;
use sp1_prover::SP1CoreProof;
use sp1_prover::SP1VerifyingKey;

#[derive(Serialize, Deserialize)]
pub struct ProveCoreRequestPayload {
    pub pk: SP1ProvingKey,
    pub stdin: SP1Stdin,
}

#[derive(Serialize, Deserialize)]
pub struct CompressRequestPayload {
    pub vk: SP1VerifyingKey,
    pub proof: SP1CoreProof,
    pub deferred_proofs: Vec<ShardProof<InnerSC>>,
}
