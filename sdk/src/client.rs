use std::{env, time::Duration};

use crate::auth::NetworkAuth;
use anyhow::{Ok, Result};
use futures::future::join_all;
use reqwest::{Client as HttpClient, Url};
use reqwest_middleware::ClientWithMiddleware as HttpClientWithMiddleware;
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use sp1_core::stark::StarkGenericConfig;
use std::time::{SystemTime, UNIX_EPOCH};
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
const DEFAULT_SP1_VERIFIER_ADDRESS: &str = "0xed2107448519345059eab9cddab42ddc78fbebe9";

pub struct NetworkClient {
    pub rpc: TwirpClient,
    pub http: HttpClientWithMiddleware,
    pub auth: NetworkAuth,
}

impl NetworkClient {
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

    pub fn get_sp1_verifier_address() -> [u8; 20] {
        let verifier_hex = env::var("SP1_VERIFIER_ADDRESS")
            .unwrap_or_else(|_| DEFAULT_SP1_VERIFIER_ADDRESS.to_string());
        let verifier_bytes = hex::decode(verifier_hex.trim_start_matches("0x"))
            .expect("Invalid SP1_VERIFIER_ADDRESS format");

        verifier_bytes
            .try_into()
            .expect("SP1_VERIFIER_ADDRESS must be 20 bytes")
    }

    async fn upload_file(&self, url: &str, data: Vec<u8>) -> Result<()> {
        self.http.put(url).body(data).send().await?;
        Ok(())
    }

    pub async fn create_proof(&self, elf: &[u8], stdin: &[u8]) -> Result<String> {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Invalid start time");
        let deadline = since_the_epoch.as_secs() + 1000;

        let create_proof_signature = self.auth.sign_create_proof_message(deadline).await?;
        let res = self
            .rpc
            .create_proof(CreateProofRequest {
                deadline,
                signature: create_proof_signature.to_vec(),
            })
            .await?;

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

        let submit_proof_signature = self.auth.sign_submit_proof_message(&res.proof_id).await?;

        self.rpc
            .submit_proof(SubmitProofRequest {
                proof_id: res.proof_id.clone(),
                signature: submit_proof_signature.to_vec(),
            })
            .await?;

        Ok(res.proof_id)
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
                proof_id: proof_id.to_string(),
            })
            .await?;

        let proof = if res.status() == ProofStatus::ProofSucceeded {
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

        Ok((res, proof))
    }

    pub async fn relay_proof(
        &self,
        proof_id: &str,
        chain_id: u32,
        verifier: [u8; 20],
        callback: [u8; 20],
        callback_data: &[u8],
    ) -> Result<String> {
        let relay_proof_signature = self
            .auth
            .sign_relay_proof_message(proof_id, chain_id, verifier, callback, callback_data)
            .await?;
        let req = RelayProofRequest {
            proof_id: proof_id.to_string(),
            chain_id,
            verifier: verifier.to_vec(),
            callback: callback.to_vec(),
            callback_data: callback_data.to_vec(),
            signature: relay_proof_signature.to_vec(),
        };
        let result = self.rpc.relay_proof(req).await?;
        Ok(result.tx_id)
    }

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
}
