use std::{env, pin::Pin, time::Duration};

use anyhow::{Ok, Result};
use futures::future::join_all;
use futures::FutureExt;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client as HttpClient, Url,
};
use reqwest_middleware::ClientWithMiddleware as HttpClientWithMiddleware;
use serde::{de::DeserializeOwned, Serialize};
use sp1_core::{stark::StarkGenericConfig, utils::BabyBearBlake3, SP1ProofWithIO};
use twirp::Client as TwirpClient;

use crate::proto::prover::{
    CreateProofRequest, GetProofStatusRequest, GetProofStatusResponse, ProofStatus,
    Sp1ProverServiceClient, SubmitProofRequest,
};

pub struct SP1ProverClient {
    pub rpc: TwirpClient,
    pub http: HttpClientWithMiddleware,
}

impl Default for SP1ProverClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SP1ProverClient {
    pub fn new() -> Self {
        let mut headers = HeaderMap::new();
        let access_token = env::var("SP1_SERVICE_ACCESS_TOKEN").unwrap();
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

        let rpc_url = env::var("SP1_SERVICE_URL").unwrap_or("http://localhost:3000/".to_string());
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

    pub async fn create_proof(&self, elf: &[u8], stdin: &[u8]) -> Result<String> {
        let res = self.rpc.create_proof(CreateProofRequest {}).await?;
        println!("res: {:?}", &res);

        let program_bytes = bincode::serialize(elf)?;
        let stdin_bytes = bincode::serialize(stdin)?;
        let program_promise = self
            .http
            .put(res.program_put_url)
            .body(program_bytes)
            .send()
            .then(|res| res.unwrap().text());
        let stdin_promise = self
            .http
            .put(res.stdin_put_url)
            .body(stdin_bytes)
            .send()
            .then(|res| res.unwrap().text());
        println!("Uploading program and stdin to the server...");
        let v: Vec<Pin<Box<dyn futures::Future<Output = _>>>> =
            vec![Box::pin(program_promise), Box::pin(stdin_promise)];
        join_all(v).await.into_iter().for_each(|res| {
            println!("res: {:?}", &res);
        });

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
