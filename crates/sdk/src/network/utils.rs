#![allow(deprecated)]

//! # Network Utils
//!
//! This module provides utility functions for the network module.

use alloy_signer::{Signature, SignerSync};
use prost::Message;

pub(crate) trait Signable: Message {
    fn sign<S: SignerSync>(&self, signer: &S) -> Signature;
}

impl<T: Message> Signable for T {
    fn sign<S: SignerSync>(&self, signer: &S) -> Signature {
        signer.sign_message_sync(&self.encode_to_vec()).unwrap()
    }
}
