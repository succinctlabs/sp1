use std::{env, time::Duration};

use crate::{
    auth::NetworkAuth,
    proto::network::{UnclaimProofRequest, UnclaimReason},
};
use anyhow::{Context, Ok, Result};
use futures::future::join_all;
use reqwest::{Client as HttpClient, Url};
use reqwest_middleware::ClientWithMiddleware as HttpClientWithMiddleware;
use serde::de::DeserializeOwned;
use sp1_prover::SP1Stdin;
use std::time::{SystemTime, UNIX_EPOCH};
use twirp::Client as TwirpClient;

use crate::proto::network::{
    ClaimProofRequest, ClaimProofResponse, CreateProofRequest, FulfillProofRequest,
    FulfillProofResponse, GetNonceRequest, GetProofRequestsRequest, GetProofRequestsResponse,
    GetProofStatusRequest, GetProofStatusResponse, GetRelayStatusRequest, GetRelayStatusResponse,
    NetworkServiceClient, ProofMode, ProofStatus, RelayProofRequest, SubmitProofRequest,
    TransactionStatus,
};

/// The default RPC endpoint for the Succinct prover network.
const DEFAULT_PROVER_NETWORK_RPC: &str = "https://rpc.succinct.xyz/";

/// The default SP1 Verifier address on all chains.
const DEFAULT_SP1_VERIFIER_ADDRESS: &str = "0xed2107448519345059eab9cddab42ddc78fbebe9";

pub struct NetworkClient {
    pub rpc: TwirpClient,
    pub http: HttpClientWithMiddleware,
    pub auth: NetworkAuth,
}

impl NetworkClient {
    // Create a new NetworkClient with the given private key for authentication.
    pub fn new(private_key: &str) -> Self {
        let auth = NetworkAuth::new(private_key);

        let rpc_url = env::var("PROVER_NETWORK_RPC")
            .unwrap_or_else(|_| DEFAULT_PROVER_NETWORK_RPC.to_string());

        let twirp_http_client = HttpClient::builder()
            .pool_max_idle_per_host(0)
            .pool_idle_timeout(Duration::from_secs(240))
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
            auth,
            rpc,
            http: http_client.into(),
        }
    }

    // Get the address for the SP1 Verifier contract.
    pub fn get_sp1_verifier_address() -> [u8; 20] {
        let verifier_hex = env::var("SP1_VERIFIER_ADDRESS")
            .unwrap_or_else(|_| DEFAULT_SP1_VERIFIER_ADDRESS.to_string());
        let verifier_bytes = hex::decode(verifier_hex.trim_start_matches("0x"))
            .expect("Invalid SP1_VERIFIER_ADDRESS format");

        verifier_bytes
            .try_into()
            .expect("SP1_VERIFIER_ADDRESS must be 20 bytes")
    }

    /// Gets the latest nonce for this auth's account.
    pub async fn get_nonce(&self) -> Result<u64> {
        let res = self
            .rpc
            .get_nonce(GetNonceRequest {
                address: self.auth.get_address().to_vec(),
            })
            .await?;
        Ok(res.nonce)
    }

    // Upload a file to the specified url.
    async fn upload_file(&self, url: &str, data: Vec<u8>) -> Result<()> {
        self.http.put(url).body(data).send().await?;
        Ok(())
    }

    // Get the status of a given proof. If the status is ProofFulfilled, the proof is also returned.
    pub async fn get_proof_status<P: DeserializeOwned>(
        &self,
        proof_id: &str,
    ) -> Result<(GetProofStatusResponse, Option<P>)> {
        let res = self
            .rpc
            .get_proof_status(GetProofStatusRequest {
                proof_id: proof_id.to_string(),
            })
            .await
            .context("Failed to get proof status")?;

        let proof = match res.status() {
            ProofStatus::ProofFulfilled => {
                log::info!("Proof request fulfilled");
                let proof_bytes = self
                    .http
                    .get(res.proof_url.as_ref().expect("no proof url"))
                    .send()
                    .await
                    .context("Failed to send HTTP request for proof")?
                    .bytes()
                    .await
                    .context("Failed to load proof bytes")?;

                Some(bincode::deserialize(&proof_bytes).context("Failed to deserialize proof")?)
            }
            _ => None,
        };

        Ok((res, proof))
    }

    // Get all the proof requests for a given status.
    pub async fn get_proof_requests(
        &self,
        status: ProofStatus,
    ) -> Result<GetProofRequestsResponse> {
        let res = self
            .rpc
            .get_proof_requests(GetProofRequestsRequest {
                status: status.into(),
            })
            .await?;

        Ok(res)
    }

    // Get the status of a relay transaction request.
    pub async fn get_relay_status(
        &self,
        tx_id: &str,
    ) -> Result<(GetRelayStatusResponse, Option<String>, Option<String>)> {
        let res = self
            .rpc
            .get_relay_status(GetRelayStatusRequest {
                tx_id: tx_id.to_string(),
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

    /// Creates a proof request for the given ELF and stdin.
    pub async fn create_proof(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
        mode: ProofMode,
    ) -> Result<String> {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Invalid start time");
        let deadline = since_the_epoch.as_secs() + 1000;

        let nonce = self.get_nonce().await?;
        let create_proof_signature = self
            .auth
            .sign_create_proof_message(nonce, deadline, mode.into())
            .await?;
        let res = self
            .rpc
            .create_proof(CreateProofRequest {
                signature: create_proof_signature.to_vec(),
                nonce,
                deadline,
                mode: mode.into(),
            })
            .await?;

        let program_bytes = bincode::serialize(elf)?;
        let stdin_bytes = bincode::serialize(&stdin)?;
        let program_promise = self.upload_file(&res.program_url, program_bytes);
        let stdin_promise = self.upload_file(&res.stdin_url, stdin_bytes);
        let v = vec![program_promise, stdin_promise];
        let mut results = join_all(v).await;
        results.pop().expect("Failed to upload stdin")?;
        results.pop().expect("Failed to upload program")?;

        let nonce = self.get_nonce().await?;
        let submit_proof_signature = self
            .auth
            .sign_submit_proof_message(nonce, &res.proof_id)
            .await?;
        self.rpc
            .submit_proof(SubmitProofRequest {
                signature: submit_proof_signature.to_vec(),
                nonce,
                proof_id: res.proof_id.clone(),
            })
            .await?;

        Ok(res.proof_id)
    }

    // Claim a proof that was requested. This commits to generating a proof and fulfilling it.
    // Returns an error if the proof is not in a PROOF_REQUESTED state.
    pub async fn claim_proof(&self, proof_id: &str) -> Result<ClaimProofResponse> {
        let nonce = self.get_nonce().await?;
        let signature = self.auth.sign_claim_proof_message(nonce, proof_id).await?;
        let res = self
            .rpc
            .claim_proof(ClaimProofRequest {
                signature,
                nonce,
                proof_id: proof_id.to_string(),
            })
            .await?;

        Ok(res)
    }

    // Unclaim a proof that was claimed. This should only be called if the proof has not been
    // fulfilled yet. Returns an error if the proof is not in a PROOF_CLAIMED state or if the caller
    // is not the claimer.
    pub async fn unclaim_proof(
        &self,
        proof_id: String,
        reason: UnclaimReason,
        description: String,
    ) -> Result<()> {
        let nonce = self.get_nonce().await?;
        let signature = self
            .auth
            .sign_unclaim_proof_message(nonce, proof_id.clone(), reason, description.clone())
            .await?;
        self.rpc
            .unclaim_proof(UnclaimProofRequest {
                signature,
                nonce,
                proof_id,
                reason: reason.into(),
                description,
            })
            .await?;

        Ok(())
    }

    // Fulfill a proof. Should only be called after the proof has been uploaded. Returns an error
    // if the proof is not in a PROOF_CLAIMED state or if the caller is not the claimer.
    pub async fn fulfill_proof(&self, proof_id: &str) -> Result<FulfillProofResponse> {
        let nonce = self.get_nonce().await?;
        let signature = self
            .auth
            .sign_fulfill_proof_message(nonce, proof_id)
            .await?;
        let res = self
            .rpc
            .fulfill_proof(FulfillProofRequest {
                signature,
                nonce,
                proof_id: proof_id.to_string(),
            })
            .await?;

        Ok(res)
    }

    // Relay a proof. Returns an error if the proof is not in a PROOF_FULFILLED state.
    pub async fn relay_proof(
        &self,
        proof_id: &str,
        chain_id: u32,
        verifier: [u8; 20],
        callback: [u8; 20],
        callback_data: &[u8],
    ) -> Result<String> {
        let nonce = self.get_nonce().await?;
        let signature = self
            .auth
            .sign_relay_proof_message(nonce, proof_id, chain_id, verifier, callback, callback_data)
            .await?;
        let req = RelayProofRequest {
            signature,
            nonce,
            proof_id: proof_id.to_string(),
            chain_id,
            verifier: verifier.to_vec(),
            callback: callback.to_vec(),
            callback_data: callback_data.to_vec(),
        };
        let result = self.rpc.relay_proof(req).await?;
        Ok(result.tx_id)
    }
}
