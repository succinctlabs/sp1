pub mod auth;
pub mod client;
pub mod prover;
mod sign_message;
#[rustfmt::skip]
pub mod proto;

use alloy::primitives::{Address, TxHash, U256};
use alloy_signer::{Signature, SignerSync};
use prost::Message;
pub use serde::{Deserialize, Serialize};

#[cfg(feature = "network-v2")]
use prost_v13 as prost;

#[derive(Clone, Debug, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum ProofStatus {
    Unspecified,
    Requested,
    Assigned,
    Fulfilled,
}

pub trait Signable: Message {
    fn sign<S: SignerSync>(&self, signer: &S) -> Signature;
}

impl<T: Message> Signable for T {
    fn sign<S: SignerSync>(&self, signer: &S) -> Signature {
        signer.sign_message_sync(&self.encode_to_vec()).unwrap()
    }
}
