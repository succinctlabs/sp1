//! # SP1 Network
//!
//! A library for interacting with the SP1 prover over the network.

pub mod client;
pub mod prover;
#[rustfmt::skip]
#[allow(missing_docs)]
#[allow(clippy::default_trait_access)]
#[allow(clippy::too_many_lines)]
pub mod proto;
pub mod builder;
mod error;
mod grpc;
pub mod prove;
mod retry;
pub mod signer;
pub mod tee;

pub mod utils;

use std::time::Duration;

pub use crate::network::{client::NetworkClient, proto::types::FulfillmentStrategy};
pub use alloy_primitives::{Address, B256};
pub use error::*;

cfg_if::cfg_if! {
    if #[cfg(not(feature = "reserved-capacity"))] {
        pub(crate) const PUBLIC_EXPLORER_URL: &str = "https://explorer.mainnet.succinct.xyz";
        pub(crate) const DEFAULT_NETWORK_RPC_URL: &str = "https://rpc.mainnet.succinct.xyz";

        // NOTE: Given the current default gas/cycle limit logic, setting a very large default
        // cycle limit will avoid stopping execution prematurely when only gas_limit is specified.
        pub(crate) const DEFAULT_CYCLE_LIMIT: u64 = 1_000_000_000_000;
    } else {
        pub(crate) const PUBLIC_EXPLORER_URL: &str = "https://explorer.reserved.succinct.xyz";
        pub(crate) const DEFAULT_NETWORK_RPC_URL: &str = "https://rpc.production.succinct.xyz";
        pub(crate) const DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;
    }
}

pub(crate) const PRIVATE_NETWORK_RPC_URL: &str = "https://rpc.private.succinct.xyz";
pub(crate) const PRIVATE_EXPLORER_URL: &str = "https://explorer-private.succinct.xyz";
pub(crate) const DEFAULT_TEE_SERVER_URL: &str = "https://tee.production.succinct.xyz";
pub(crate) const TEE_NETWORK_RPC_URL: &str = "https://sp1-lumiere.xyz";

pub(crate) const DEFAULT_AUCTION_TIMEOUT_DURATION: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_GAS_LIMIT: u64 = 1_000_000_000;
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 14400;
