use std::{borrow::Cow, fmt};

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use sp1_prover::SP1ProvingKey;

#[derive(Clone, Serialize, Deserialize)]
pub struct CreateProgramRequestBody<'a> {
    pub vk_hash: B256,
    pub pk: Cow<'a, SP1ProvingKey>,
}

impl fmt::Debug for CreateProgramRequestBody<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateProgramRequestBody").field("vk_hash", &self.vk_hash).finish()
    }
}
