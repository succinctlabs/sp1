use crate::{
    local::LocalProver,
    proof::SP1ProofWithPublicValues,
    prover::Prover,
    SP1VerificationError,
};

#[cfg(feature = "network-v2")]
use crate::network_v2::{NetworkProver, DEFAULT_PROVER_NETWORK_RPC};

use anyhow::Result;
use sp1_core_executor::{ExecutionError, ExecutionReport};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{SP1ProvingKey, SP1VerifyingKey};
use std::sync::Arc;
use crate::ProofOpts;

mod request;
pub use request::DynProofRequest;
mod builder;
pub use builder::{ProverClientBuilder, None};

pub struct ProverClient {
    inner: Box<dyn Prover>,
}

impl ProverClient {
    pub fn builder() -> ProverClientBuilder<None> {
        ProverClientBuilder::new()
    }

    #[deprecated(note = "Use ProverClient::builder() instead")]
    pub fn new() -> Self {
        Self::create_from_env()
    }

    fn create_from_env() -> Self {
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

    pub async fn setup(&self, elf: Arc<[u8]>) -> Arc<SP1ProvingKey> {
        self.inner.setup(elf).await
    }

    pub async fn execute(
        &self,
        elf: Arc<[u8]>,
        stdin: SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError> {
        self.inner.execute(elf, stdin).await
    }

    pub fn prove<'a>(&'a self, pk: &'a Arc<SP1ProvingKey>, stdin: SP1Stdin) -> DynProofRequest<'a> {
        DynProofRequest::new(&*self.inner, pk, stdin, ProofOpts::default())
    }

    pub async fn verify(
        &self,
        proof: Arc<SP1ProofWithPublicValues>,
        vk: Arc<SP1VerifyingKey>,
    ) -> Result<(), SP1VerificationError> {
        self.inner.verify(proof, vk).await
    }
}
