//! # Network Utils
//!
//! This module provides utility functions for the network module.

#![allow(deprecated)]

use anyhow::Result;
use prost::Message;

use std::cmp::{max, min};

use super::signer::NetworkSigner;

/// Trait for signing network protobuf messages.
pub(crate) trait Signable: Message {
    async fn sign(&self, signer: &NetworkSigner) -> Result<Vec<u8>>;
}

impl<T: Message> Signable for T {
    async fn sign(&self, signer: &NetworkSigner) -> Result<Vec<u8>> {
        let signature = signer.sign_message(self.encode_to_vec().as_slice()).await?;
        Ok(signature.as_bytes().to_vec())
    }
}

/// Sign a message and return the raw signature object.
pub(crate) async fn sign_raw(
    message: &[u8],
    signer: &NetworkSigner,
) -> Result<alloy_primitives::Signature> {
    Ok(signer.sign_message(message).await?)
}

/// Sign a message and return signature bytes with Ethereum-style recovery ID.
pub(crate) async fn sign_message(message: &[u8], signer: &NetworkSigner) -> Result<Vec<u8>> {
    let signature = signer.sign_message(message).await?;
    let bytes = signature.as_bytes();

    // Extract r,s (first 64 bytes) and v (last byte).
    let mut signature_bytes = bytes[..64].to_vec();
    let v = bytes[64];

    // Ethereum uses 27 + v for the recovery id.
    signature_bytes.push(v + 27);

    Ok(signature_bytes)
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

/// Get the default RPC URL for the given network mode.
#[must_use]
pub fn get_default_rpc_url_for_mode(network_mode: super::NetworkMode) -> String {
    match network_mode {
        super::NetworkMode::Mainnet => super::MAINNET_RPC_URL.to_string(),
        super::NetworkMode::Reserved => super::RESERVED_RPC_URL.to_string(),
    }
}

/// Get the explorer URL for the given network mode.
#[must_use]
pub fn get_explorer_url_for_mode(network_mode: super::NetworkMode) -> &'static str {
    match network_mode {
        super::NetworkMode::Mainnet => super::MAINNET_EXPLORER_URL,
        super::NetworkMode::Reserved => super::RESERVED_EXPLORER_URL,
    }
}

/// Get the default cycle limit for the given network mode.
#[must_use]
pub fn get_default_cycle_limit_for_mode(network_mode: super::NetworkMode) -> u64 {
    match network_mode {
        super::NetworkMode::Mainnet => super::MAINNET_DEFAULT_CYCLE_LIMIT,
        super::NetworkMode::Reserved => super::RESERVED_DEFAULT_CYCLE_LIMIT,
    }
}
