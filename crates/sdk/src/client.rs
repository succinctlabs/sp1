use crate::{
    local::{LocalProver, LocalProverBuilder},
    network::{NetworkProver, NetworkProverBuilder},
    network_v2::DEFAULT_PROVER_NETWORK_RPC,
    opts::ProofOpts,
    proof::SP1ProofWithPublicValues,
    prover::Prover,
};
use anyhow::Result;
use sp1_core_executor::{ExecutionError, ExecutionReport};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{SP1ProvingKey, SP1VerifyingKey};
use std::env;

pub struct None;

pub struct ProverClient {
    inner: Box<dyn Prover>,
}

pub struct ProverClientBuilder<T> {
    inner_builder: T,
}

impl ProverClient {
    pub fn builder() -> ProverClientBuilder<None> {
        ProverClientBuilder { inner_builder: None }
    }

    #[deprecated(note = "Use ProverClient::builder() instead")]
    pub fn new() -> Self {
        Self::create_from_env()
    }

    fn create_from_env() -> Self {
        match env::var("SP1_PROVER").unwrap_or("local".to_string()).as_str() {
            "network" => {
                let rpc_url = env::var("PROVER_NETWORK_RPC")
                    .unwrap_or_else(|_| DEFAULT_PROVER_NETWORK_RPC.to_string());
                let private_key = env::var("SP1_PRIVATE_KEY").unwrap_or_default();

                let network_prover = NetworkProver::new(rpc_url, private_key);
                ProverClient { inner: Box::new(network_prover) }
            }
            _ => {
                let local_prover = LocalProver::new();
                ProverClient { inner: Box::new(local_prover) }
            }
        }
    }

    pub async fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.inner.setup(elf).await
    }

    pub async fn execute(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError> {
        self.inner.execute(elf, stdin).await
    }

    pub async fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
    ) -> Result<SP1ProofWithPublicValues> {
        let opts = ProofOpts::default();
        self.inner.prove_with_options(pk, stdin, &opts).await
    }

    pub async fn prove_with_options(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        opts: &ProofOpts,
    ) -> Result<SP1ProofWithPublicValues> {
        self.inner.prove_with_options(pk, stdin, opts).await
    }

    pub async fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), crate::provers::SP1VerificationError> {
        self.inner.verify(proof, vk).await
    }
}

impl ProverClientBuilder<None> {
    pub fn local(self) -> ProverClientBuilder<LocalProverBuilder> {
        ProverClientBuilder { inner_builder: LocalProver::builder() }
    }

    pub fn network(self) -> ProverClientBuilder<NetworkProverBuilder> {
        ProverClientBuilder { inner_builder: NetworkProver::builder() }
    }

    pub fn from_env(self) -> ProverClient {
        ProverClient::create_from_env()
    }
}

impl ProverClientBuilder<LocalProverBuilder> {
    pub fn build(self) -> ProverClient {
        ProverClient { inner: Box::new(self.inner_builder.build()) }
    }
}

impl ProverClientBuilder<NetworkProverBuilder> {
    pub fn with_rpc_url(mut self, url: String) -> Self {
        self.inner_builder = self.inner_builder.with_rpc_url(url);
        self
    }

    pub fn with_private_key(mut self, key: String) -> Self {
        self.inner_builder = self.inner_builder.with_private_key(key);
        self
    }

    pub fn build(self) -> ProverClient {
        ProverClient { inner: Box::new(self.inner_builder.build()) }
    }
}
