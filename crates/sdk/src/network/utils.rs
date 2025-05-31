//! # Network Utils
//!
//! This module provides utility functions for the network module.

#![allow(deprecated)]
use prost::Message;

use k256::ecdsa::{RecoveryId, Signature, SigningKey};

pub(crate) trait Signable: Message {
    fn sign(&self, signer: &SigningKey) -> Vec<u8>;
}

impl<T: Message> Signable for T {
    fn sign(&self, signer: &SigningKey) -> Vec<u8> {
        let (sig, v) = sign_raw(self.encode_to_vec().as_slice(), signer);
        let mut signature_bytes = sig.to_vec();
        signature_bytes.push(v.to_byte());

        signature_bytes
    }
}

pub(crate) fn sign_raw(message: &[u8], signer: &SigningKey) -> (Signature, RecoveryId) {
    let message = alloy_primitives::utils::eip191_hash_message(message);
    signer.sign_prehash_recoverable(message.as_slice()).unwrap()
}
