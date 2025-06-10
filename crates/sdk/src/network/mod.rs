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

pub use crate::network::{client::NetworkClient, proto::types::FulfillmentStrategy};
pub use alloy_primitives::{Address, B256};
use alloy_sol_types::eip712_domain;
pub use error::*;
use std::sync::LazyLock;

pub(crate) const DEFAULT_NETWORK_RPC_URL: &str = "https://rpc.production.succinct.xyz/";
pub(crate) const DEFAULT_TEE_SERVER_URL: &str = "https://tee.production.succinct.xyz";

pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 14400;
pub(crate) const DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;
pub(crate) const DEFAULT_GAS_LIMIT: u64 = 1_000_000_000;

pub(crate) const DEFAULT_AUCTIONEER_ADDRESS: &str = "0x29cf94C0809Bac6DFC837B5DA92D0c7F088E7Da1";
pub(crate) const DEFAULT_EXECUTOR_ADDRESS: &str = "0x29cf94C0809Bac6DFC837B5DA92D0c7F088E7Da1";
pub(crate) const DEFAULT_VERIFIER_ADDRESS: &str = "0x29cf94C0809Bac6DFC837B5DA92D0c7F088E7Da1";
pub(crate) static SPN_SEPOLIA_V1_DOMAIN: LazyLock<B256> = LazyLock::new(|| {
    let domain = eip712_domain! {
        name: "Succinct Prover Network",
        version: "1.0.0",
        chain_id: 11155111,
    };
    domain.separator()
});
