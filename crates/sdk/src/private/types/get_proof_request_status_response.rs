use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{network::proto::types::FulfillmentStatus, SP1ProofWithPublicValues};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetProofRequestStatusResponse {
    pub fulfillment_status: FulfillmentStatus,
    pub proof: Option<Arc<SP1ProofWithPublicValues>>,
}
