use std::{env, time::Duration};

use anyhow::{Ok, Result};
use futures::future::join_all;
use log::info;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client as HttpClient, Url,
};
use reqwest_middleware::ClientWithMiddleware as HttpClientWithMiddleware;
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
pub use sp1_core::stark::StarkGenericConfig;
use tokio::time::sleep;
use twirp::Client as TwirpClient;

use crate::{
    proto::network::{
        CreateProofRequest, GetProofStatusRequest, GetProofStatusResponse, GetRelayStatusRequest,
        GetRelayStatusResponse, NetworkServiceClient, ProofStatus, RelayProofRequest,
        SubmitProofRequest, TransactionStatus,
    },
    SP1ProofWithIO,
};

const DEFAULT_PROVER_NETWORK_RPC: &str = "https://rpc.succinct.xyz/";
const DEFAULT_SP1_VERIFIER_ADDRESS: &str = "0x9a39f368676f7a5cbbfe8ea33c258c4536b5398f";

pub struct NetworkClient {
    pub rpc: TwirpClient,
    pub http: HttpClientWithMiddleware,
}

impl NetworkClient {
    pub fn with_token(access_token: String) -> Self {
        let rpc_url = env::var("PROVER_NETWORK_RPC")
            .unwrap_or_else(|_| DEFAULT_PROVER_NETWORK_RPC.to_string());
        Self::with_url(access_token, rpc_url)
    }

    pub fn with_url(access_token: String, rpc_url: String) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", access_token)).unwrap(),
        );
        let twirp_http_client = HttpClient::builder()
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(Duration::from_secs(240))
            .default_headers(headers)
            .build()
            .unwrap();

        let rpc =
            TwirpClient::new(Url::parse(&rpc_url).unwrap(), twirp_http_client, vec![]).unwrap();

        let http_client = HttpClient::builder()
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(Duration::from_secs(240))
            .build()
            .unwrap();
        Self {
            rpc,
            http: http_client.into(),
        }
    }

    pub fn get_sp1_verifier_address() -> [u8; 20] {
        let verifier_hex = env::var("SP1_VERIFIER_ADDRESS")
            .unwrap_or_else(|_| DEFAULT_SP1_VERIFIER_ADDRESS.to_string());
        let verifier_bytes = hex::decode(verifier_hex.trim_start_matches("0x"))
            .expect("Invalid SP1_VERIFIER_ADDRESS format");

        verifier_bytes
            .try_into()
            .expect("Verifier address must be 20 bytes")
    }

    async fn upload_file(&self, url: &str, data: Vec<u8>) -> Result<()> {
        self.http.put(url).body(data).send().await?;
        Ok(())
    }

    pub async fn create_proof(&self, elf: &[u8], stdin: &[u8]) -> Result<String> {
        // TODO: Naming convention here is unclear. We should have separate methods for creating the
        // proof with the RPC and the client for interfacing with the API.
        let res = self.rpc.create_proof(CreateProofRequest {}).await?;

        let mut program_bytes = Vec::new();
        elf.serialize(&mut Serializer::new(&mut program_bytes))?;
        let mut stdin_bytes = Vec::new();
        stdin.serialize(&mut Serializer::new(&mut stdin_bytes))?;
        let program_promise = self.upload_file(&res.program_put_url, program_bytes);
        let stdin_promise = self.upload_file(&res.stdin_put_url, stdin_bytes);
        let v = vec![program_promise, stdin_promise];
        let mut results = join_all(v).await;
        results.pop().expect("Failed to upload stdin")?;
        results.pop().expect("Failed to upload program")?;

        self.rpc
            .submit_proof(SubmitProofRequest { id: res.id.clone() })
            .await?;

        Ok(res.id)
    }

    pub async fn poll_proof<SC: for<'de> Deserialize<'de> + Serialize + StarkGenericConfig>(
        &self,
        proof_id: &str,
        max_polls: u64,
        poll_interval: u64,
    ) -> Result<SP1ProofWithIO<SC>> {
        // Query every 10 seconds for the proof status.
        // TODO: Proof status should be an object (instead of a tuple).
        // TODO: THe STARK config is annoying.

        for _ in 0..max_polls {
            info!("Polling proof status");
            let proof_status = self.get_proof_status::<SC>(proof_id).await;
            if proof_status.is_ok() {
                let proof_status = proof_status.unwrap();
                info!("Proof status: {:?}", proof_status.0.status());
                if proof_status.0.status() == ProofStatus::ProofSucceeded {
                    if let Some(proof_data) = proof_status.1 {
                        println!("Proof data: {:?}", proof_data.public_values.buffer.data);
                        return Ok(proof_data);
                    }
                }
            }
            sleep(Duration::from_secs(poll_interval)).await;
        }

        Err(anyhow::anyhow!("Proof failed or was rejected"))
    }

    pub async fn get_proof_status<
        SC: for<'de> Deserialize<'de> + Serialize + StarkGenericConfig,
    >(
        &self,
        proof_id: &str,
    ) -> Result<(GetProofStatusResponse, Option<SP1ProofWithIO<SC>>)> {
        let res = self
            .rpc
            .get_proof_status(GetProofStatusRequest {
                id: proof_id.to_string(),
            })
            .await?;

        let result = if res.status() == ProofStatus::ProofSucceeded {
            let proof = self
                .http
                .get(res.result_get_url.clone())
                .send()
                .await?
                .bytes()
                .await?;
            let mut de = Deserializer::new(&proof[..]);
            Some(Deserialize::deserialize(&mut de).expect("Failed to deserialize proof"))
        } else {
            None
        };

        Ok((res, result))
    }

    pub async fn relay_proof(
        &self,
        proof_id: &str,
        chain_id: u32,
        verifier: [u8; 20],
        callback: [u8; 20],
        callback_data: &[u8],
    ) -> Result<String> {
        let req = RelayProofRequest {
            proof_id: proof_id.to_string(),
            chain_id,
            verifier: verifier.to_vec(),
            callback: callback.to_vec(),
            callback_data: callback_data.to_vec(),
        };
        let result = self.rpc.relay_proof(req).await?;
        Ok(result.id)
    }

    pub async fn get_relay_status(
        &self,
        tx_id: &str,
    ) -> Result<(GetRelayStatusResponse, Option<String>, Option<String>)> {
        let res = self
            .rpc
            .get_relay_status(GetRelayStatusRequest {
                id: tx_id.to_string(),
            })
            .await?;

        let tx_hash = match res.status() {
            TransactionStatus::TransactionScheduled => None,
            _ => Some(format!("0x{}", hex::encode(res.tx_hash.clone()))),
        };

        let simulation_url = match res.status() {
            TransactionStatus::TransactionFailed => Some(res.simulation_url.clone()),
            _ => None,
        };

        Ok((res, tx_hash, simulation_url))
    }
}
