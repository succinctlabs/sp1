use crate::{
    local::{LocalProver, LocalProverBuilder},
    prover::Prover,
};

#[cfg(feature = "network-v2")]
use crate::network_v2::{NetworkProver, NetworkProverBuilder};

use super::ProverClient;

pub struct None;

pub struct ProverClientBuilder<T> {
    inner_builder: T,
}

impl Default for ProverClientBuilder<None> {
    fn default() -> Self {
        Self::new()
    }
}

impl ProverClientBuilder<None> {
    pub fn new() -> Self {
        ProverClientBuilder { inner_builder: None }
    }

    pub fn local(self) -> ProverClientBuilder<LocalProverBuilder> {
        ProverClientBuilder { inner_builder: LocalProver::builder() }
    }

    #[cfg(feature = "network-v2")]
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

    pub fn with_default_timeout(mut self, timeout: u64) -> Self {
        self.inner_builder = self.inner_builder.with_default_timeout(timeout);
        self
    }

    pub fn with_default_cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.inner_builder = self.inner_builder.with_default_cycle_limit(cycle_limit);
        self
    }
}

#[cfg(feature = "network-v2")]
impl ProverClientBuilder<NetworkProverBuilder> {
    pub fn rpc_url(mut self, url: String) -> Self {
        self.inner_builder = self.inner_builder.rpc_url(url);
        self
    }

    pub fn private_key(mut self, key: String) -> Self {
        self.inner_builder = self.inner_builder.private_key(key);
        self
    }
}

pub trait BuildableProver: Sized {
    fn build_prover(self) -> Box<dyn Prover>;

    fn with_default_timeout(self, timeout: u64) -> Self;

    fn with_default_cycle_limit(self, cycle_limit: u64) -> Self;
}

impl BuildableProver for LocalProverBuilder {
    fn build_prover(self) -> Box<dyn Prover> {
        Box::new(self.build())
    }

    fn with_default_timeout(self, timeout: u64) -> Self {
        self.with_timeout(timeout)
    }

    fn with_default_cycle_limit(self, cycle_limit: u64) -> Self {
        self.with_cycle_limit(cycle_limit)
    }
}

#[cfg(feature = "network-v2")]
impl BuildableProver for NetworkProverBuilder {
    fn build_prover(self) -> Box<dyn Prover> {
        Box::new(self.build())
    }

    fn with_default_timeout(self, timeout: u64) -> Self {
        self.with_timeout(timeout)
    }

    fn with_default_cycle_limit(self, cycle_limit: u64) -> Self {
        self.with_cycle_limit(cycle_limit)
    }
}
