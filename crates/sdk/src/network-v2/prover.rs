use std::pin::Pin;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use sp1_core_executor::{ExecutionError, ExecutionReport, SP1Context};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{components::DefaultProverComponents, SP1Prover, SP1_CIRCUIT_VERSION};
use sp1_prover::{SP1ProvingKey, SP1VerifyingKey};
use std::future::{Future, IntoFuture};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::task;
use tokio::time::sleep;

use crate::Mode;
use crate::network_v2::retry::{self, with_retry};
use crate::network_v2::{
    client::{NetworkClient, DEFAULT_PROVER_NETWORK_RPC},
    proto::network::{ExecutionStatus, FulfillmentStatus, FulfillmentStrategy, ProofMode},
    types::{HashType, RequestId, VerifyingKeyHash},
    Error,
};
use crate::ProofOpts;
use crate::proof::SP1ProofWithPublicValues;
use crate::prover::Prover;
use crate::request::{DEFAULT_CYCLE_LIMIT, DEFAULT_TIMEOUT};
use crate::verify;
use crate::SP1VerificationError;

/// The default fulfillment strategy to use for proof requests.
pub const DEFAULT_FULFILLMENT_STRATEGY: FulfillmentStrategy = FulfillmentStrategy::Hosted;

/// The minimum allowed timeout for a proof request to be fulfilled (10 seconds).
pub const MIN_TIMEOUT_SECS: u64 = 10;

/// The maximum allowed timeout for a proof request to be fulfilled (24 hours).
pub const MAX_TIMEOUT_SECS: u64 = 86400;

/// The number of seconds to wait between checking the status of a proof request.
pub const STATUS_CHECK_INTERVAL_SECS: u64 = 2;

/// An implementation of [crate::ProverClient] that can generate proofs on a remote RPC server.
pub struct NetworkProver {
    prover: Arc<SP1Prover<DefaultProverComponents>>,
    network_client: NetworkClient,
    timeout: u64,
    max_cycle_limit: Option<u64>,

}

pub struct NetworkProverBuilder {
    rpc_url: Option<String>,
    private_key: Option<String>,
    timeout: Option<u64>,
    max_cycle_limit: Option<u64>,
}

impl NetworkProver {
    /// Creates a new `NetworkProver` with the given private private_key.
    /// This function uses default timeout and cycle limit.
    pub fn new(rpc_url: String, private_key: String) -> Self {
        Self {
            prover: Arc::new(SP1Prover::new()),
            network_client: NetworkClient::new(&private_key).rpc_url(rpc_url),
            timeout: DEFAULT_TIMEOUT, 
            max_cycle_limit: None,
        }
    }

    /// Creates a new network prover builder. See [`NetworkProverBuilder`] for more details.
    pub fn builder() -> NetworkProverBuilder {
        NetworkProverBuilder::new()
    }

    /// Get the underlying SP1 prover.
    pub fn sp1_prover(&self) -> &SP1Prover {
        &self.prover
    }

    /// Create a new proof request.
    pub fn prove<'a>(
        &'a self,
        pk: &'a SP1ProvingKey,
        stdin: SP1Stdin,
    ) -> NetworkProofRequest<'a> {
        NetworkProofRequest::new(self, pk, stdin)
    }
}

impl NetworkProver {
    /// Get the cycle limit to used for a proof request.
    ///
    /// The cycle limit is determined according to the following priority:
    /// 1. If a cycle limit was explicitly set, use the specified value
    /// 2. If simulation is enabled (default), calculate the limit by simulating
    /// 3. Otherwise use the default cycle limit
    #[allow(clippy::must_use_candidate)]
    fn get_cycle_limit(
        &self,
        elf: &[u8],
        stdin: &SP1Stdin,
        cycle_limit: Option<u64>,
        skip_simulation: bool,
    ) -> Result<u64, Error> {
        // If cycle_limit was explicitly set, use it.
        if let Some(limit) = cycle_limit {
            return Ok(limit);
        }

        // If simulation is enabled (default), simulate to get the limit.
        if !skip_simulation {
            let (_, report) = self
                .prover
                .execute(elf, stdin, Default::default())
                .map_err(|_| Error::SimulationFailed)?;
            Ok(report.total_instruction_count())
        } else {
            // Skip simulation was set but no explicit cycle limit, use default.
            Ok(DEFAULT_CYCLE_LIMIT)
        }
    }

    /// Registers a program if it is not already registered.
    async fn register_program(&self, vk: &SP1VerifyingKey, elf: &[u8]) -> Result<VerifyingKeyHash> {
        self.network_client.register_program(vk, elf).await
    }

    /// Requests a proof from the prover network, returning the request ID.
    #[allow(clippy::too_many_arguments)]
    async fn request_proof(
        &self,
        vk_hash: &VerifyingKeyHash,
        stdin: &SP1Stdin,
        version: &str,
        mode: ProofMode,
        strategy: FulfillmentStrategy,
        timeout: u64,
        cycle_limit: u64,
    ) -> Result<RequestId> {
        // Request the proof with retries.
        let (tx_hash, request_id) = retry::with_retry(
            || async {
                self.network_client
                    .request_proof(vk_hash, stdin, version, mode, strategy, timeout, cycle_limit)
                    .await
            },
            timeout,
            "requesting proof",
        )
        .await?;

        log::info!("Created request {} in transaction {}", request_id, tx_hash);

        if self.network_client.get_rpc_url() == DEFAULT_PROVER_NETWORK_RPC {
            log::info!("View in explorer: {}", request_id.explorer_url());
        }

        Ok(request_id)
    }

    /// Waits for the proof request to be fulfilled by the prover network after it has been
    /// submitted.
    ///
    /// Additionally, different failure modes are checked:
    /// - if the deadline is exceeded, throws a `RequestDeadlineExceeded` error
    /// - if the request is unexecutable, throws a `RequestUnexecutable` error
    /// - if the request is unfulfillable, throws a `RequestUnfulfillable` error
    async fn wait_proof<P: DeserializeOwned>(
        &self,
        request_id: &RequestId,
        timeout: u64,
    ) -> Result<P, Error> {
        let mut is_assigned = false;

        loop {
            // Get the status with retries.
            let (status, maybe_proof) = with_retry(
                || async { self.network_client.get_proof_request_status(request_id).await },
                timeout,
                "getting proof status",
            )
            .await?;

            // Check the deadline.
            if status.deadline < Instant::now().elapsed().as_secs() {
                return Err(Error::RequestDeadlineExceeded { request_id: request_id.clone() });
            }

            // Check the execution status.
            if let Ok(ExecutionStatus::Unexecutable) =
                ExecutionStatus::try_from(status.execution_status)
            {
                return Err(Error::RequestUnexecutable { request_id: request_id.clone() });
            }

            // Check the fulfillment status.
            match FulfillmentStatus::try_from(status.fulfillment_status) {
                Ok(FulfillmentStatus::Fulfilled) => {
                    return Ok(maybe_proof.unwrap());
                }
                Ok(FulfillmentStatus::Assigned) => {
                    if !is_assigned {
                        log::info!("Proof request assigned, proving...");
                        is_assigned = true;
                    }
                }
                Ok(FulfillmentStatus::Unfulfillable) => {
                    return Err(Error::RequestUnfulfillable { request_id: request_id.clone() });
                }
                _ => {}
            }

            sleep(Duration::from_secs(STATUS_CHECK_INTERVAL_SECS)).await;
        }
    }
}

#[allow(clippy::new_without_default)]
impl NetworkProverBuilder {
    /// Creates a new network prover builder.
    pub fn new() -> Self {
        Self { rpc_url: None, private_key: None, timeout: None, max_cycle_limit: None }
    }

    /// Sets the RPC URL for the prover network.
    ///
    /// This configures the endpoint that will be used for all network operations.
    /// If not set, the default RPC URL will be used.
    pub fn rpc_url(mut self, url: String) -> Self {
        self.rpc_url = Some(url);
        self
    }

    /// Sets the private key to use for the prover network.
    ///
    /// This is required and must be set before building the prover.
    pub fn private_key(mut self, key: String) -> Self {
        self.private_key = Some(key);
        self
    }

    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_cycle_limit(mut self, max_cycle_limit: u64) -> Self {
        self.max_cycle_limit = Some(max_cycle_limit);
        self
    }

    /// Builds the prover with the given configuration.
    pub fn build(self) -> NetworkProver {
         NetworkProver {
            prover: Arc::new(SP1Prover::new()),
            network_client: NetworkClient::new(&self.private_key.expect("A private key set on the builder")).rpc_url(self.rpc_url.expect("An RPC URL set on the builder")),
            timeout: self.timeout.unwrap_or(DEFAULT_TIMEOUT), 
            max_cycle_limit: self.max_cycle_limit,
        }
    }
}

pub struct NetworkProofRequest<'a> {
    prover: &'a NetworkProver,
    pk: &'a SP1ProvingKey,
    stdin: SP1Stdin,
    mode: ProofMode,
    version: String,
    timeout: u64,
    cycle_limit: Option<u64>,
    skip_simulation: bool,
    strategy: FulfillmentStrategy,
}

impl<'a> NetworkProofRequest<'a> {
    pub fn new(prover: &'a NetworkProver, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> Self {
        Self {
            prover,
            pk,
            stdin,
            mode: Mode::default().into(),
            version: SP1_CIRCUIT_VERSION.to_string(),
            timeout: prover.timeout,
            cycle_limit: prover.max_cycle_limit,
            skip_simulation: false,
            strategy: DEFAULT_FULFILLMENT_STRATEGY,
        }
    }

    fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode.into();
        self
    }

    pub fn core(mut self) -> Self {
        self.mode = ProofMode::Core;
        self
    }

    pub fn compressed(mut self) -> Self {
        self.mode = ProofMode::Compressed;
        self
    }

    pub fn plonk(mut self) -> Self {
        self.mode = ProofMode::Plonk;
        self
    }

    pub fn groth16(mut self) -> Self {
        self.mode = ProofMode::Groth16;
        self
    }

    pub fn with_version(mut self, version: String) -> Self {
        self.version = version;
        self
    }

    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.cycle_limit = Some(cycle_limit);
        self
    }

    pub fn skip_simulation(mut self) -> Self {
        self.skip_simulation = true;
        self
    }

    pub fn with_strategy(mut self, strategy: FulfillmentStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    pub fn run(self) -> Result<SP1ProofWithPublicValues> {
        Runtime::new().unwrap().block_on(async move { self.run_inner().await })
    }
}

impl<'a> NetworkProofRequest<'a> {
    async fn run_inner(self) -> Result<SP1ProofWithPublicValues> {
        // Register the program.
        let vk_hash = self.prover.register_program(&self.pk.vk, &self.pk.elf).await?;

        // Get the cycle limit.
        let cycle_limit = self.prover.get_cycle_limit(
            &self.pk.elf,
            &self.stdin,
            self.cycle_limit,
            self.skip_simulation,
        )?;

        // Request the proof.
        let request_id = self
            .prover
            .request_proof(
                &vk_hash,
                &self.stdin,
                &self.version,
                self.mode,
                self.strategy,
                self.timeout,
                cycle_limit,
            )
            .await?;

        // Wait for proof generation.
        let proof: SP1ProofWithPublicValues =
            self.prover.wait_proof(&request_id, self.timeout).await?;

        Ok(proof)
    }
}

#[async_trait]
impl Prover for NetworkProver {
    async fn setup(&self, elf: Arc<[u8]>) -> Arc<SP1ProvingKey> {
        let prover = Arc::clone(&self.prover);
        task::spawn_blocking(move || {
            let (pk, _vk) = prover.setup(&elf);
            Arc::new(pk)
        })
        .await
        .unwrap()
    }

    #[cfg(feature = "blocking")]
    fn setup_sync(&self, elf: &[u8]) -> Arc<SP1ProvingKey> {
        let (pk, _vk) = self.prover.setup(elf);
        Arc::new(pk)
    }

    async fn execute(
        &self,
        elf: Arc<[u8]>,
        stdin: SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError> {
        let prover = Arc::clone(&self.prover);
        task::spawn_blocking(move || prover.execute(&elf, &stdin, SP1Context::default()))
            .await
            .unwrap()
    }

    #[cfg(feature = "blocking")]
    fn execute_sync(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError> {
        self.prover.execute(elf, &stdin, SP1Context::default())
    }

    async fn prove_with_options(
        &self,
        pk: &Arc<SP1ProvingKey>,
        stdin: SP1Stdin,
        opts: ProofOpts,
    ) -> Result<SP1ProofWithPublicValues> {
        self.prove(pk, stdin)
            .with_mode(opts.mode)
            .with_timeout(opts.timeout)
            .with_cycle_limit(opts.cycle_limit)
            .await
    }

    #[cfg(feature = "blocking")]
    fn prove_with_options_sync(
        &self,
        pk: &Arc<SP1ProvingKey>,
        stdin: SP1Stdin,
        opts: ProofOpts,
    ) -> Result<SP1ProofWithPublicValues> {
        self.prove(pk, stdin)
            .with_mode(opts.mode)
            .with_timeout(opts.timeout)
            .with_cycle_limit(opts.cycle_limit)
            .run()
    }

    async fn verify(
        &self,
        proof: Arc<SP1ProofWithPublicValues>,
        vk: Arc<SP1VerifyingKey>,
    ) -> Result<(), SP1VerificationError> {
        let prover = Arc::clone(&self.prover);
        task::spawn_blocking(move || verify::verify(&prover, SP1_CIRCUIT_VERSION, &proof, &vk))
            .await
            .unwrap()
    }

    #[cfg(feature = "blocking")]
    fn verify_sync(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        verify::verify(&self.prover, SP1_CIRCUIT_VERSION, proof, vk)
    }
}

impl<'a> IntoFuture for NetworkProofRequest<'a> {
    type Output = Result<SP1ProofWithPublicValues>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move { self.run_inner().await })
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use sp1_core_machine::io::SP1Stdin;

//     const TEST_PRIVATE_KEY: &str =
//         "0000000000000000000000000000000000000000000000000000000000000001";

//     #[test]
//     fn test_proof_opts_configuration() {
//         let opts = ProofOpts {
//             timeout: Some(Duration::from_secs(100)),
//             cycle_limit: Some(1000),
//             fulfillment_strategy: Some(FulfillmentStrategy::Hosted),
//             skip_simulation: true,
//             ..Default::default()
//         };

//         assert_eq!(opts.timeout.unwrap().as_secs(), 100);
//         assert_eq!(opts.cycle_limit.unwrap(), 1000);
//         assert_eq!(opts.fulfillment_strategy.unwrap(), FulfillmentStrategy::Hosted);
//         assert!(opts.skip_simulation);
//     }

//     #[test]
//     fn test_proof_opts_defaults() {
//         let opts = ProofOpts::default();

//         assert_eq!(opts.timeout, None);
//         assert_eq!(opts.cycle_limit, None);
//         assert_eq!(opts.fulfillment_strategy, None);
//         assert!(!opts.skip_simulation);
//     }

//     #[test]
//     fn test_cycle_limit_handling() {
//         let prover = NetworkProver::new(TEST_PRIVATE_KEY);
//         let dummy_stdin = SP1Stdin::default();
//         let dummy_elf = test_artifacts::FIBONACCI_ELF;

//         // Test with explicit cycle limit
//         let result = prover.get_cycle_limit(dummy_elf, &dummy_stdin, Some(1000), false);
//         assert_eq!(result.unwrap(), 1000);

//         // Test with simulation disabled, no explicit limit
//         let result = prover.get_cycle_limit(dummy_elf, &dummy_stdin, None, true);
//         assert_eq!(result.unwrap(), DEFAULT_CYCLE_LIMIT);

//         // Test with simulation enabled
//         let result = prover.get_cycle_limit(dummy_elf, &dummy_stdin, None, false);
//         assert!(result.is_ok());
//     }

//     #[test]
//     fn test_timeout_clamping() {
//         // Test minimum bound
//         let timeout_secs = NetworkProver::get_timeout_secs(Some(Duration::from_secs(1)));
//         assert_eq!(timeout_secs, MIN_TIMEOUT_SECS);

//         // Test maximum bound
//         let timeout_secs =
//             NetworkProver::get_timeout_secs(Some(Duration::from_secs(MAX_TIMEOUT_SECS + 1000)));
//         assert_eq!(timeout_secs, MAX_TIMEOUT_SECS);

//         // Test value within bounds
//         let valid_timeout = 3600;
//         let timeout_secs =
//             NetworkProver::get_timeout_secs(Some(Duration::from_secs(valid_timeout)));
//         assert_eq!(timeout_secs, valid_timeout);

//         // Test default when None
//         let timeout_secs = NetworkProver::get_timeout_secs(None);
//         assert_eq!(timeout_secs, DEFAULT_TIMEOUT_SECS);
//     }
// }
