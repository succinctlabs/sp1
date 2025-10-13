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
pub mod validation;

pub mod utils;

use std::time::Duration;

pub use crate::network::{client::NetworkClient, proto::types::FulfillmentStrategy};
pub use alloy_primitives::{Address, B256};
pub use error::*;
pub use utils::{
    get_default_cycle_limit_for_mode, get_default_rpc_url_for_mode, get_explorer_url_for_mode,
};

/// The network mode to use for the prover client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Mainnet network using auction-based proving.
    Mainnet,
    /// Reserved capacity network for hosted/reserved proving.
    Reserved,
}

#[allow(clippy::derivable_impls)]
impl Default for NetworkMode {
    fn default() -> Self {
        cfg_if::cfg_if! {
            if #[cfg(feature = "reserved-capacity")] {
                NetworkMode::Reserved
            } else {
                NetworkMode::Mainnet
            }
        }
    }
}

impl std::str::FromStr for NetworkMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mainnet" | "auction" => Ok(NetworkMode::Mainnet),
            "reserved" | "hosted" => Ok(NetworkMode::Reserved),
            _ => Err(format!("Invalid network mode: {s}")),
        }
    }
}

pub(crate) const MAINNET_EXPLORER_URL: &str = "https://explorer.succinct.xyz";
pub(crate) const MAINNET_RPC_URL: &str = "https://rpc.mainnet.succinct.xyz";
pub(crate) const RESERVED_EXPLORER_URL: &str = "https://explorer.reserved.succinct.xyz";
pub(crate) const RESERVED_RPC_URL: &str = "https://rpc.production.succinct.xyz";

pub(crate) const PRIVATE_NETWORK_RPC_URL: &str = "https://rpc.private.succinct.xyz";
pub(crate) const PRIVATE_EXPLORER_URL: &str = "https://explorer-private.succinct.xyz";
pub(crate) const DEFAULT_TEE_SERVER_URL: &str = "https://tee.production.succinct.xyz";
pub(crate) const TEE_NETWORK_RPC_URL: &str = "https://tee.sp1-lumiere.xyz";

pub(crate) const DEFAULT_AUCTION_TIMEOUT_DURATION: Duration = Duration::from_secs(30);
pub(crate) const MAINNET_DEFAULT_CYCLE_LIMIT: u64 = 1_000_000_000_000;
pub(crate) const RESERVED_DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;
pub(crate) const DEFAULT_GAS_LIMIT: u64 = 1_000_000_000;
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 14400;
