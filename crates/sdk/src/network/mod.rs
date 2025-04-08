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

pub use crate::network::{client::NetworkClient, proto::network::FulfillmentStrategy};
pub use alloy_primitives::B256;
pub use error::*;

pub(crate) const DEFAULT_NETWORK_RPC_URL: &str = "https://rpc.production.succinct.xyz/";
pub(crate) const DEFAULT_TEE_SERVER_URL: &str = "https://tee.production.succinct.xyz";

pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 14400;
pub(crate) const DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;
pub(crate) const DEFAULT_GAS_LIMIT: u64 = 1_000_000_000;
