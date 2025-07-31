use std::borrow::Cow;

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

use crate::{network::proto::types::ProofMode, SP1Stdin};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestProofRequestBody<'a> {
    pub vk_hash: B256,
    pub mode: ProofMode,
    pub stdin: Cow<'a, SP1Stdin>,
    pub cycle_limit: u64,
    pub gas_limit: u64,
    pub deadline: u64,
}
