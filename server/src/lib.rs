#[rustfmt::skip]
pub mod proto {
    pub mod api;
}

use serde::{Deserialize, Serialize};
use sp1_core::io::SP1Stdin;
use sp1_core::utils::SP1ProverOpts;
use sp1_prover::types::SP1ProvingKey;

#[derive(Serialize, Deserialize)]
pub struct ProveCoreRequestPayload {
    pub pk: SP1ProvingKey,
    pub stdin: SP1Stdin,
}
