//! # Network Utils
//!
//! This module provides utility functions for the network module.

#![allow(deprecated)]

use std::cmp::{max, min};

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

/// Calculate the timeout for a proof request based on gas limit.
///
/// Uses a base timeout of 5 minutes plus 1 second per 2000000 prover gas. The timeout is capped at
/// 4 hours.
pub(crate) fn calculate_timeout_from_gas_limit(gas_limit: u64) -> u64 {
    let base_timeout = 300; // 5 minutes
    let gas_based_timeout = gas_limit / 2_000_000;
    min(max(base_timeout, gas_based_timeout), 14400)
}
