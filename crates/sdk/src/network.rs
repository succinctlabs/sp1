use anyhow::Result;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{SP1ProvingKey, SP1VerifyingKey, SP1_CIRCUIT_VERSION};
use std::future::{Future, IntoFuture};
use std::pin::Pin;

use crate::mode::Mode;
use crate::network_v2::FulfillmentStrategy;
use crate::network_v2::{Error, RequestId, VerifyingKeyHash};
use crate::request::ProofRequest;
use crate::{network_v2::NetworkClient, CpuProver, SP1ProofWithPublicValues};

pub struct NetworkProver {
    cpu_prover: CpuProver,
    network_client: NetworkClient,
}

impl NetworkProver {
    pub fn new(rpc_url: String, private_key: String) -> Self {
        Self {
            cpu_prover: CpuProver::new(),
            network_client: NetworkClient::new(&private_key).with_rpc_url(rpc_url),
        }
    }

    pub fn cpu_prover(&self) -> &CpuProver {
        &self.cpu_prover
    }

    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.network_client.mode = mode;
        self
    }

    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.network_client.timeout_secs = Some(secs);
        self
    }

    pub fn cycle_limit(mut self, limit: u64) -> Self {
        self.network_client.cycle_limit = Some(limit);
        self
    }

    pub fn skip_simulation(mut self, skip: bool) -> Self {
        self.network_client.skip_simulation = skip;
        self
    }

    pub fn strategy(mut self, strategy: FulfillmentStrategy) -> Self {
        self.network_client.fulfillment_strategy = Some(strategy);
        self
    }

    #[allow(clippy::must_use_candidate)]
    fn get_cycle_limit(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
        cycle_limit: Option<u64>,
        skip_simulation: bool,
    ) -> Result<u64, Error> {
        todo!()
    }

    /// Registers a program if it is not already registered.
    pub async fn register_program(
        &self,
        vk: &SP1VerifyingKey,
        elf: &[u8],
    ) -> Result<VerifyingKeyHash> {
        todo!()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn request_proof(
        &self,
        vk_hash: &VerifyingKeyHash,
        stdin: &SP1Stdin,
        version: &str,
        mode: Mode,
        strategy: FulfillmentStrategy,
        timeout_secs: u64,
        cycle_limit: u64,
    ) -> Result<RequestId> {
        todo!()
    }

    pub async fn wait_proof<P: DeserializeOwned>(
        &self,
        request_id: &RequestId,
        timeout_secs: u64,
    ) -> Result<P, Error> {
        todo!()
    }

    // // Ensure the program is registered.
    // let vk_hash = self.register_program(&request.pk.vk, &request.pk.elf).await?;

    // // Get the configured settings.
    // let stdin = request.stdin;
    // let version = request.version;
    // let mode = request.mode;
    // let strategy = request.fulfillment_strategy.unwrap_or(DEFAULT_FULFILLMENT_STRATEGY);
    // let timeout_secs = Self::get_timeout_secs(request.timeout_sec);
    // let cycle_limit = self.get_cycle_limit(
    // 	&request.pk.elf,
    // 	&stdin,
    // 	request.cycle_limit,
    // 	request.skip_simulation,
    // )?;

    // // Request the proof.
    // let request_id = self
    // 	.request_proof(&vk_hash, &stdin, version, mode, strategy, timeout_secs, cycle_limit)
    // 	.await?;

    // // Wait for the proof to be generated.
    // self.wait_proof(&request_id, timeout_secs).await

    pub fn prove_with_options(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> NetworkProofRequest {
        NetworkProofRequest::new(self, pk, stdin)
    }
}

pub struct NetworkProofRequest<'a> {
    pub prover: &'a NetworkProver,
    pub pk: &'a SP1ProvingKey,
    pub stdin: SP1Stdin,
    pub version: String,
    pub mode: Mode,
    pub fulfillment_strategy: Option<FulfillmentStrategy>,
    pub timeout_sec: Option<u64>,
    pub cycle_limit: Option<u64>,
    pub skip_simulation: bool,
}

impl<'a> NetworkProofRequest<'a> {
    pub fn new(prover: &'a NetworkProver, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> Self {
        Self {
            prover,
            pk,
            stdin,
            version: SP1_CIRCUIT_VERSION.to_owned(),
            mode: Mode::default(),
            fulfillment_strategy: None,
            timeout_sec: None,
            cycle_limit: None,
            skip_simulation: false,
        }
    }
    pub async fn run(self) -> Result<SP1ProofWithPublicValues> {
        self.prover.prove_with_options(&self.pk, self.stdin).await
    }
}

impl<'a> IntoFuture for NetworkProofRequest<'a> {
    type Output = Result<SP1ProofWithPublicValues>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move { self.run().await })
    }
}

#[async_trait]
impl Prover for NetworkProver {
    fn cpu_prover(&self) -> &CpuProver {
        self.cpu_prover()
    }

    async fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1ProofWithPublicValues> {
        self.prove_with_options(pk, stdin).await
    }
}

impl ProofRequest for NetworkProofRequest<'_> {
    async fn run(self) -> Result<SP1ProofWithPublicValues> {
        self.prover.prove_with_options(&self.pk, self.stdin).await
    }
}
