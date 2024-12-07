mod client;
mod error;
mod json;
mod prover;
mod sign_message;
mod types;
#[rustfmt::skip]
mod proto;

pub use client::*;
pub use error::*;
pub use proto::network::*;
pub use prover::*;
pub use types::*;

use alloy_signer::{Signature, SignerSync};
use prost::Message;

pub trait Signable: Message {
    fn sign<S: SignerSync>(&self, signer: &S) -> Signature;
}

impl<T: Message> Signable for T {
    fn sign<S: SignerSync>(&self, signer: &S) -> Signature {
        signer.sign_message_sync(&self.encode_to_vec()).unwrap()
    }
}
