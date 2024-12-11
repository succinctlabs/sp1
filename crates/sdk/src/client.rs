use crate::{
    local::{LocalProver, LocalProverBuilder},
    network::{NetworkProver, NetworkProverBuilder},
    prover::Prover,
};
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
        Self::builder().from_env()
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
        match env::var("SP1_PROVER").unwrap_or("local".to_string()).as_str() {
            "network" => self.network().build(),
            _ => self.local().build(),
        }
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
