use std::{env, time::Duration};

use anyhow::{Context, Ok, Result};
use futures::future::join_all;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client as HttpClient, Url,
};
use reqwest_middleware::ClientWithMiddleware as HttpClientWithMiddleware;
use serde::{de::DeserializeOwned, Serialize};
use sp1_core::stark::StarkGenericConfig;
use twirp::Client as TwirpClient;

use crate::{
    proto::prover::{
        CreateProofRequest, GetProofStatusRequest, GetProofStatusResponse, ProofStatus,
        Sp1ProverServiceClient, SubmitProofRequest,
    },
    SP1ProofWithIO,
};

pub struct SP1ProverServiceClient {
    pub rpc: TwirpClient,
    pub http: HttpClientWithMiddleware,
}

const DEFAULT_SP1_SERVICE_URL: &str = "https://rpc.succinct.xyz/";

impl SP1ProverServiceClient {
    pub fn with_token(access_token: String) -> Self {
        let rpc_url =
            env::var("SP1_SERVICE_URL").unwrap_or_else(|_| DEFAULT_SP1_SERVICE_URL.to_string());
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

    async fn upload_file(&self, url: &str, data: Vec<u8>) -> Result<()> {
        self.http.put(url).body(data).send().await?;
        Ok(())
    }

    pub async fn create_proof(&self, elf: &[u8], stdin: &[u8]) -> Result<String> {
        let res = self.rpc.create_proof(CreateProofRequest {}).await?;

        let program_bytes = bincode::serialize(elf)?;
        let stdin_bytes = bincode::serialize(stdin)?;
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

    pub async fn get_proof_status<SC: StarkGenericConfig + Serialize + DeserializeOwned>(
        &self,
        proof_id: &str,
    ) -> Result<(GetProofStatusResponse, Option<SP1ProofWithIO<SC>>)> {
        let res = self
            .rpc
            .get_proof_status(GetProofStatusRequest {
                id: proof_id.to_string(),
            })
            .await?;

        let result = if res.status() == ProofStatus::Succeeded {
            let proof = self
                .http
                .get(res.result_get_url.clone())
                .send()
                .await?
                .bytes()
                .await?;
            Some(bincode::deserialize(&proof)?)
        } else {
            None
        };

        Ok((res, result))
    }
}
