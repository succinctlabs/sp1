use anyhow::Result;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use sp1_core_executor::{ExecutionError, ExecutionReport, SP1Context};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::components::DefaultProverComponents;
use sp1_prover::{SP1Prover, SP1ProvingKey, SP1VerifyingKey, SP1_CIRCUIT_VERSION};
use std::future::{Future, IntoFuture};
use std::pin::Pin;

use crate::mode::Mode;
use crate::opts::ProofOpts;
use crate::prover::Prover;
use crate::provers::SP1VerificationError;
use crate::request::ProofRequest;

use crate::network_v2::FulfillmentStrategy;
use crate::network_v2::DEFAULT_PROVER_NETWORK_RPC;
use crate::network_v2::{Error, RequestId, VerifyingKeyHash};
use crate::verify;
use crate::{network_v2::NetworkClient, proof::SP1ProofWithPublicValues};

pub struct NetworkProver {
    prover: SP1Prover<DefaultProverComponents>,
    network_client: NetworkClient,
}

pub struct NetworkProverBuilder {
    rpc_url: Option<String>,
    private_key: Option<String>,
}

impl NetworkProver {
    pub fn new(rpc_url: String, private_key: String) -> Self {
        Self {
            prover: SP1Prover::new(),
            network_client: NetworkClient::new(&private_key).with_rpc_url(rpc_url),
        }
    }

    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.network_client.mode = mode.into();
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

    pub fn prove_with_options<'a>(
        &'a self,
        pk: &'a SP1ProvingKey,
        stdin: &'a SP1Stdin,
    ) -> NetworkProofRequest<'a> {
        NetworkProofRequest::new(self, pk, stdin)
    }

    pub fn builder() -> NetworkProverBuilder {
        NetworkProverBuilder::new()
    }
}

impl NetworkProverBuilder {
    pub fn new() -> Self {
        Self { rpc_url: None, private_key: None }
    }

    pub fn rpc_url(mut self, url: String) -> Self {
        self.rpc_url = Some(url);
        self
    }

    pub fn private_key(mut self, key: String) -> Self {
        self.private_key = Some(key);
        self
    }

    pub fn build(self) -> NetworkProver {
        NetworkProver::new(
            self.rpc_url.unwrap_or_else(|| DEFAULT_PROVER_NETWORK_RPC.to_string()),
            self.private_key.expect("private key is required"),
        )
    }
}

pub struct NetworkProofRequest<'a> {
    prover: &'a NetworkProver,
    pk: &'a SP1ProvingKey,
    stdin: &'a SP1Stdin,
    version: String,
    mode: Mode,
    fulfillment_strategy: Option<FulfillmentStrategy>,
    timeout_sec: Option<u64>,
    cycle_limit: Option<u64>,
    skip_simulation: bool,
}

impl<'a> NetworkProofRequest<'a> {
    pub fn new(prover: &'a NetworkProver, pk: &'a SP1ProvingKey, stdin: &'a SP1Stdin) -> Self {
        Self {
            prover,
            pk,
            stdin,
            // TODO fill in defaults
            version: SP1_CIRCUIT_VERSION.to_owned(),
            mode: Mode::default(),
            fulfillment_strategy: None,
            timeout_sec: None,
            cycle_limit: None,
            skip_simulation: false,
        }
    }

    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout_sec = Some(timeout);
        self
    }

    pub fn with_strategy(mut self, strategy: FulfillmentStrategy) -> Self {
        self.fulfillment_strategy = Some(strategy);
        self
    }

    pub fn with_cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.cycle_limit = Some(cycle_limit);
        self
    }

    async fn run(self) -> Result<SP1ProofWithPublicValues> {
        // Ensure the program is registered
        let vk_hash = self.prover.register_program(&self.pk.vk, &self.pk.elf).await?;

        // Get configured settings
        let strategy = self.fulfillment_strategy.unwrap_or(FulfillmentStrategy::Hosted);
        let timeout_secs = self.timeout_sec.unwrap_or(3600); // Default 1 hour
        let cycle_limit = self.prover.get_cycle_limit(
            &self.pk.elf,
            &self.stdin,
            self.cycle_limit,
            self.skip_simulation,
        )?;

        // Request the proof
        let request_id = self
            .prover
            .request_proof(
                &vk_hash,
                &self.stdin,
                &self.version,
                self.mode,
                strategy,
                timeout_secs,
                cycle_limit,
            )
            .await?;

        // Wait for proof generation - specify the return type explicitly
        let proof: SP1ProofWithPublicValues = self
            .prover
            .wait_proof(&request_id, timeout_secs)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to wait for proof: {}", e))?;

        Ok(proof)
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
    async fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }
    async fn execute(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError> {
        self.prover.execute(elf, stdin, SP1Context::default())
    }

    async fn prove_with_options(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        opts: &ProofOpts,
    ) -> Result<SP1ProofWithPublicValues> {
        let request = NetworkProofRequest::new(self, pk, stdin)
            .with_mode(opts.mode)
            .with_timeout(opts.timeout)
            .with_cycle_limit(opts.cycle_limit);
        request.run().await
    }

    #[cfg(feature = "blocking")]
    fn prove_with_options_sync(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        opts: &ProofOpts,
    ) -> Result<SP1ProofWithPublicValues> {
        let request = NetworkProofRequest::new(self, pk, stdin);
        request.run()
    }

    async fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        verify::verify(&self.prover, SP1_CIRCUIT_VERSION, proof, vk)
    }
}
