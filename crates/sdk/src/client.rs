use crate::{
    local::LocalProver, prover::Prover, SP1VerificationError, types::{Elf, SP1ProofWithPublicValues},
};

#[cfg(feature = "network-v2")]
use crate::network_v2::{NetworkProver, DEFAULT_PROVER_NETWORK_RPC};

use crate::ProofOpts;
use anyhow::Result;
use sp1_core_executor::{ExecutionError, ExecutionReport};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use crate::types::{SP1ProvingKey, SP1VerifyingKey};

#[cfg(feature = "network-v2")]
use std::env;

mod request;
pub use request::DynProofRequest;
mod builder;
pub use builder::{None, ProverClientBuilder};

pub struct ProverClient {
    inner: Box<dyn Prover>,
}

#[allow(clippy::new_without_default)]
impl ProverClient {
    pub fn builder() -> ProverClientBuilder<None> {
        ProverClientBuilder::new()
    }

    #[deprecated(note = "Use ProverClient::builder() instead")]
    pub fn new() -> Self {
        Self::from_env()
    }

    fn from_env() -> Self {
        #[cfg(feature = "network-v2")]
        match std::env::var("SP1_PROVER").unwrap_or("local".to_string()).as_str() {
            "network" => {
                let rpc_url = env::var("PROVER_NETWORK_RPC")
                    .unwrap_or_else(|_| DEFAULT_PROVER_NETWORK_RPC.to_string());
                let private_key = env::var("SP1_PRIVATE_KEY").unwrap_or_default();

                let network_prover = NetworkProver::new(rpc_url, private_key);
                ProverClient { inner: Box::new(network_prover) }
            }
            _ => {
                let local_prover = LocalProver::default();
                ProverClient { inner: Box::new(local_prover) }
            }
        }

        #[cfg(not(feature = "network-v2"))]
        {
            let local_prover = LocalProver::default();
            ProverClient { inner: Box::new(local_prover) }
        }
    }

    pub async fn setup(&self, elf: &Elf) -> SP1ProvingKey {
        self.inner.setup(elf).await
    }

    #[cfg(feature = "blocking")]
    pub async fn blocking_setup(&self, elf: &Elf) -> SP1ProvingKey {
        self.inner.setup_sync(elf)
    }

    pub async fn execute(
        &self,
        elf: &Elf,
        stdin: SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError> {
        self.inner.execute(elf, stdin).await
    }

    #[cfg(feature = "blocking")]
    pub async fn blocking_execute(
        &self,
        elf: &Elf,
        stdin: SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError> {
        self.inner.execute_sync(elf, stdin)
    }

    pub fn prove<'a>(&'a self, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> DynProofRequest<'a> {
        DynProofRequest::new(&*self.inner, pk, stdin, ProofOpts::default())
    }

    pub async fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        self.inner.verify(proof, vk).await
    }

    #[cfg(feature = "blocking")]
    pub async fn verify_sync(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        self.inner.verify_sync(proof, vk)
    }
}
