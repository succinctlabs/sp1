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
pub mod tee;

pub mod utils;

use std::time::Duration;

pub use crate::network::{client::NetworkClient, proto::types::FulfillmentStrategy};
pub use alloy_primitives::{Address, B256};
pub use error::*;

cfg_if::cfg_if! {
    if #[cfg(not(feature = "reserved-capacity"))] {
        pub(crate) const PUBLIC_EXPLORER_URL: &str = "https://explorer.sepolia.succinct.xyz";
        pub(crate) const DEFAULT_NETWORK_RPC_URL: &str = "https://rpc.sepolia.succinct.xyz";
    } else {
        pub(crate) const PUBLIC_EXPLORER_URL: &str = "https://explorer.succinct.xyz";
        pub(crate) const DEFAULT_NETWORK_RPC_URL: &str = "https://rpc.production.succinct.xyz";
    }
}

pub(crate) const PRIVATE_NETWORK_RPC_URL: &str = "https://rpc.private.succinct.xyz";
pub(crate) const PRIVATE_EXPLORER_URL: &str = "https://explorer-private.succinct.xyz";
pub(crate) const DEFAULT_TEE_SERVER_URL: &str = "https://tee.production.succinct.xyz";

pub(crate) const DEFAULT_AUCTION_TIMEOUT_DURATION: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;
pub(crate) const DEFAULT_GAS_LIMIT: u64 = 1_000_000_000;
