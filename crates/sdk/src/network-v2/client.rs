use std::{env, time::Duration};

use crate::network_v2::auth::NetworkAuth;
use crate::network_v2::proto::network::{
    GetFilteredProofRequestsRequest, GetFilteredProofRequestsResponse,
};
use anyhow::{Context, Ok, Result};
use futures::{future::join_all, Future};
use reqwest::{Client as HttpClient, Url};
use reqwest_middleware::ClientWithMiddleware as HttpClientWithMiddleware;
use serde::de::DeserializeOwned;
use sp1_core_machine::io::SP1Stdin;
use std::{
    result::Result::Ok as StdOk,
    time::{SystemTime, UNIX_EPOCH},
};
use twirp::{Client as TwirpClient, ClientError};

use crate::network::proto::network::{
    ClaimProofRequest, ClaimProofResponse, CreateProofRequest, FulfillProofRequest,
    FulfillProofResponse, GetNonceRequest, GetProofRequestsRequest, GetProofRequestsResponse,
    GetProofStatusRequest, GetProofStatusResponse, NetworkServiceClient, ProofMode, ProofStatus,
    SubmitProofRequest,
};

/// The default RPC endpoint for the Succinct prover network.
pub const DEFAULT_PROVER_NETWORK_RPC: &str = "http://localhost:3000";

/// The timeout for a proof request to be fulfilled.
const TIMEOUT: Duration = Duration::from_secs(60 * 60);

pub struct NetworkClient {
    pub auth: NetworkAuth,
    pub rpc: TwirpClient,
    pub http: HttpClientWithMiddleware,
}

impl NetworkClient {
    /// Returns the currently configured RPC endpoint for the Succinct prover network.
    pub fn rpc_url() -> String {
        env::var("PROVER_NETWORK_RPC").unwrap_or_else(|_| DEFAULT_PROVER_NETWORK_RPC.to_string())
    }

    /// Create a new NetworkClient with the given private key for authentication.
    pub fn new(private_key: &str) -> Self {
        let auth = NetworkAuth::new(private_key);

        let twirp_http_client = HttpClient::builder()
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(Duration::from_secs(240))
            .build()
            .unwrap();

        let rpc_url = Self::rpc_url();
        let rpc =
            TwirpClient::new(Url::parse(&rpc_url).unwrap(), twirp_http_client, vec![]).unwrap();

        let http_client = HttpClient::builder()
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(Duration::from_secs(240))
            .build()
            .unwrap();

        Self { auth, rpc, http: http_client.into() }
    }
}
