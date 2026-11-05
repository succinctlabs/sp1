//! # Network Utils
//!
//! This module provides utility functions for the network module.

#![allow(deprecated)]

use anyhow::Result;
use prost::Message;

use std::cmp::{max, min};

use super::signer::SignerSource;

/// Trait for signing network protobuf messages.
pub(crate) trait Signable: Message {
    async fn sign(&self, signer: &SignerSource) -> Result<Vec<u8>>;
}

impl<T: Message> Signable for T {
    async fn sign(&self, signer: &SignerSource) -> Result<Vec<u8>> {
        let signature = signer.sign_message(self.encode_to_vec().as_slice()).await?;
        Ok(signature.as_bytes().to_vec())
    }
}

/// Sign a message and return the raw signature object.
pub(crate) async fn sign_raw(
    message: &[u8],
    signer: &SignerSource,
) -> Result<alloy_primitives::Signature> {
    Ok(signer.sign_message(message).await?)
}

/// Sign a message and return signature bytes with Ethereum-style recovery ID.
pub(crate) async fn sign_message(message: &[u8], signer: &SignerSource) -> Result<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::{Signable, SignerSource};
    use crate::network::{
        proto::{auction_types, base_types},
        signer::NetworkSigner,
    };

    async fn assert_legacy_signing_bytes(message: impl Signable, expected: &str) {
        // Captured from these same public message types with prost 0.13.5.
        let bytes = hex::decode(expected).unwrap();
        assert_eq!(message.encode_to_vec(), bytes);
        let signer = NetworkSigner::local(&"01".repeat(32)).unwrap();
        let signature = signer.sign_message(&bytes).await.unwrap();
        let source = SignerSource::from(signer);
        assert_eq!(message.sign(&source).await.unwrap(), signature.as_bytes());
    }

    #[tokio::test]
    async fn reserved_proof_request_preserves_signing_bytes() {
        let body = base_types::RequestProofRequestBody {
            nonce: 150,
            vk_hash: vec![0x11; 32],
            version: "sp1-v6.1.0".into(),
            mode: 2,
            strategy: 2,
            stdin_uri: "stdins/test".into(),
            deadline: 1_800_000_000,
            cycle_limit: 100_000,
            gas_limit: 200_000,
            min_auction_period: 30,
            whitelist: vec![vec![0x22; 20], vec![0x33; 20]],
            stdin_private: true,
        };
        assert_legacy_signing_bytes(body, concat!(
            "08960112201111111111111111111111111111111111111111111111111111111111111111",
            "1a0a7370312d76362e312e3020022802320b737464696e732f746573743880a4a7da0640a08d0648c09a0c501e",
            "5a1422222222222222222222222222222222222222225a1433333333333333333333333333333333333333336001"
        )).await;
    }

    #[tokio::test]
    async fn auction_proof_request_preserves_signing_bytes() {
        let body = auction_types::RequestProofRequestBody {
            nonce: 150,
            vk_hash: vec![0x11; 32],
            version: "sp1-v6.1.0".into(),
            mode: 2,
            strategy: 2,
            stdin_uri: "stdins/test".into(),
            deadline: 1_800_000_000,
            cycle_limit: 100_000,
            gas_limit: 200_000,
            min_auction_period: 30,
            whitelist: vec![vec![0x22; 20], vec![0x33; 20]],
            stdin_private: true,
            domain: vec![0x44; 32],
            auctioneer: vec![0x55; 20],
            executor: vec![0x66; 20],
            verifier: vec![0x77; 20],
            public_values_hash: Some(vec![0x88; 32]),
            base_fee: "123".into(),
            max_price_per_pgu: "456".into(),
            variant: 1,
            treasury: vec![0x99; 20],
        };
        assert_legacy_signing_bytes(body, concat!(
            "08960112201111111111111111111111111111111111111111111111111111111111111111",
            "1a0a7370312d76362e312e3020022802320b737464696e732f746573743880a4a7da0640a08d0648c09a0c501e",
            "5a1422222222222222222222222222222222222222225a143333333333333333333333333333333333333333",
            "62204444444444444444444444444444444444444444444444444444444444444444",
            "6a14555555555555555555555555555555555555555572146666666666666666666666666666666666666666",
            "7a1477777777777777777777777777777777777777778201208888888888888888888888888888888888888888888888888888888888888888",
            "8a0103313233920103343536980101a201149999999999999999999999999999999999999999a80101"
        )).await;
    }
}
