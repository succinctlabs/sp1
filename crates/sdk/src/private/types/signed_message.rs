use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    pub signature: Vec<u8>,
    pub message: Vec<u8>,
}
