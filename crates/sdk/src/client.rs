use crate::{
    local::{LocalProver, LocalProverBuilder},
    network_v2::DEFAULT_PROVER_NETWORK_RPC,
    network_v2::{NetworkProver, NetworkProverBuilder},
    opts::ProofOpts,
    proof::SP1ProofWithPublicValues,
    prover::Prover,
    request::DynProofRequest,
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

    pub fn prove<'a>(&'a self, pk: &'a SP1ProvingKey, stdin: &'a SP1Stdin) -> DynProofRequest<'a> {
        DynProofRequest::new(&*self.inner, pk, stdin, ProofOpts::default())
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

impl<T: BuildableProver> ProverClientBuilder<T> {
    pub fn build(self) -> ProverClient {
        ProverClient { inner: self.inner_builder.build_prover() }
    }
}

impl ProverClientBuilder<NetworkProverBuilder> {
    pub fn with_rpc_url(mut self, url: String) -> Self {
        self.inner_builder = self.inner_builder.rpc_url(url);
        self
    }

    pub fn with_private_key(mut self, key: String) -> Self {
        self.inner_builder = self.inner_builder.private_key(key);
        self
    }
}

pub trait BuildableProver {
    fn build_prover(self) -> Box<dyn Prover>;
}

impl BuildableProver for LocalProverBuilder {
    fn build_prover(self) -> Box<dyn Prover> {
        Box::new(self.build())
    }
}

impl BuildableProver for NetworkProverBuilder {
    fn build_prover(self) -> Box<dyn Prover> {
        Box::new(self.build())
    }
}
