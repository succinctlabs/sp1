pub mod client;
pub mod prover;
mod sign_message;
#[rustfmt::skip]
pub mod proto;

use alloy_signer::{Signature, SignerSync};
use prost::Message;
pub use serde::{Deserialize, Serialize};

pub trait Signable: Message {
    fn sign<S: SignerSync>(&self, signer: &S) -> Signature;
}

impl<T: Message> Signable for T {
    fn sign<S: SignerSync>(&self, signer: &S) -> Signature {
        signer.sign_message_sync(&self.encode_to_vec()).unwrap()
    }
}
