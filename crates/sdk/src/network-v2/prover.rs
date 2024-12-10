use std::time::{Duration, Instant};

use anyhow::Result;
use backoff::{future::retry, Error as BackoffError, ExponentialBackoff};
use serde::de::DeserializeOwned;
use tokio::time::sleep;
use tonic::Code;

use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{components::DefaultProverComponents, SP1Prover, SP1_CIRCUIT_VERSION};
use sp1_stark::SP1ProverOpts;

use crate::network_v2::{
    client::{NetworkClient, DEFAULT_PROVER_NETWORK_RPC},
    proto::network::{ExecutionStatus, FulfillmentStatus, FulfillmentStrategy, ProofMode},
    types::{HashType, RequestId, VerifyingKeyHash},
    Error,
};
use crate::{
    block_on,
    provers::{CpuProver, ProofOpts, ProverType},
    NetworkProverBuilder, Prover, SP1Context, SP1ProofKind, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1VerifyingKey,
};

/// The default fulfillment strategy to use for proof requests.
pub const DEFAULT_FULFILLMENT_STRATEGY: FulfillmentStrategy = FulfillmentStrategy::Hosted;

/// The default timeout for a proof request to be fulfilled (4 hours).
pub const DEFAULT_TIMEOUT_SECS: u64 = 14400;

/// The minimum allowed timeout for a proof request to be fulfilled (10 seconds).
pub const MIN_TIMEOUT_SECS: u64 = 10;

/// The maximum allowed timeout for a proof request to be fulfilled (24 hours).
pub const MAX_TIMEOUT_SECS: u64 = 86400;

/// The default cycle limit for a proof request if simulation and the cycle limit is not explicitly
/// set.
pub const DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;

/// The number of seconds to wait between checking the status of a proof request.
pub const STATUS_INTERVAL_SECS: u64 = 2;

/// An implementation of [crate::ProverClient] that can generate proofs on a remote RPC server.
pub struct NetworkProver {
    client: NetworkClient,
    local_prover: CpuProver,
}

impl NetworkProver {
    /// Creates a new `NetworkProver` with the given private key.
    pub fn new(private_key: &str) -> Self {
        let version = SP1_CIRCUIT_VERSION;
        log::info!("Client circuit version: {}", version);

        Self { client: NetworkClient::new(private_key), local_prover: CpuProver::new() }
    }

    /// Sets up the proving key and verifying key for the given ELF.
    pub fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.local_prover.setup(elf)
    }

    /// Sets the RPC URL for the prover network.
    ///
    /// This configures the endpoint that will be used for all network operations.
    /// If not set, the default RPC URL will be used.
    pub fn with_rpc_url(mut self, rpc_url: impl Into<String>) -> Self {
        self.client = self.client.with_rpc_url(rpc_url);
        self
    }

    /// Creates a new network prover builder. See [`NetworkProverBuilder`] for more details.
    pub fn builder() -> NetworkProverBuilder {
        NetworkProverBuilder::default()
    }

    /// Gets the clamped timeout in seconds from the provided options.
    fn get_timeout_secs(timeout: Option<Duration>) -> u64 {
        timeout
            .map(|d| d.as_secs().clamp(MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS))
            .unwrap_or(DEFAULT_TIMEOUT_SECS)
    }

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
                .local_prover
                .sp1_prover()
                .execute(elf, stdin, Default::default())
                .map_err(|_| Error::SimulationFailed)?;
            Ok(report.total_instruction_count())
        } else {
            // Skip simulation was set but no explicit cycle limit, use default.
            Ok(DEFAULT_CYCLE_LIMIT)
        }
    }

    /// Registers a program if it is not already registered.
    pub async fn register_program(
        &self,
        vk: &SP1VerifyingKey,
        elf: &[u8],
    ) -> Result<VerifyingKeyHash> {
        self.client.register_program(vk, elf).await
    }

    /// Requests a proof from the prover network, returning the request ID.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_proof(
        &self,
        vk_hash: &VerifyingKeyHash,
        stdin: &SP1Stdin,
        version: &str,
        mode: ProofMode,
        strategy: FulfillmentStrategy,
        timeout_secs: u64,
        cycle_limit: u64,
    ) -> Result<RequestId> {
        // Request the proof with retries.
        let (tx_hash, request_id) = with_retry(
            || async {
                self.client
                    .request_proof(
                        vk_hash,
                        stdin,
                        version,
                        mode,
                        strategy,
                        timeout_secs,
                        cycle_limit,
                    )
                    .await
            },
            timeout_secs,
            "requesting proof",
        )
        .await?;

        log::info!("Created request {} in transaction {}", request_id, tx_hash);

        if self.client.rpc_url() == DEFAULT_PROVER_NETWORK_RPC {
            log::info!("View in explorer: {}", request_id.explorer_url());
        }

        Ok(request_id)
    }

    /// Waits for the proof request to be fulfilled by the prover network.
    ///
    /// The proof request must have already been submitted. This function will return a
    /// `RequestTimedOut` error if the request does not received a response within the timeout.
    pub async fn wait_proof<P: DeserializeOwned>(
        &self,
        request_id: &RequestId,
        timeout_secs: u64,
    ) -> Result<P, Error> {
        let mut is_assigned = false;
        let start_time = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        loop {
            // Check if we've exceeded the timeout.
            if start_time.elapsed() > timeout {
                return Err(Error::RequestTimedOut { request_id: request_id.clone() });
            }
            let remaining_timeout = timeout.saturating_sub(start_time.elapsed());

            // Get the status with retries.
            let (status, maybe_proof) = with_retry(
                || async { self.client.get_proof_request_status(request_id).await },
                remaining_timeout.as_secs(),
                "getting proof status",
            )
            .await?;

            // Check the deadline.
            if status.deadline < Instant::now().elapsed().as_secs() {
                return Err(Error::RequestTimedOut { request_id: request_id.clone() });
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

            sleep(Duration::from_secs(STATUS_INTERVAL_SECS)).await;
        }
    }

    /// Requests a proof from the prover network and waits for it to be returned.
    pub async fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        opts: ProofOpts,
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues, Error> {
        // Ensure the program is registered.
        let vk_hash = self.register_program(&pk.vk, &pk.elf).await?;

        // Get the configured settings.
        let version = SP1_CIRCUIT_VERSION;
        let mode = kind.into();
        let strategy = opts.fulfillment_strategy.unwrap_or(DEFAULT_FULFILLMENT_STRATEGY);
        let timeout_secs = Self::get_timeout_secs(opts.timeout);
        let cycle_limit =
            self.get_cycle_limit(&pk.elf, &stdin, opts.cycle_limit, opts.skip_simulation)?;

        // Request the proof.
        let request_id = self
            .request_proof(&vk_hash, &stdin, version, mode, strategy, timeout_secs, cycle_limit)
            .await?;

        // Wait for the proof to be generated.
        self.wait_proof(&request_id, timeout_secs).await
    }
}

impl Prover<DefaultProverComponents> for NetworkProver {
    fn id(&self) -> ProverType {
        ProverType::Network
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.local_prover.setup(elf)
    }

    fn sp1_prover(&self) -> &SP1Prover {
        self.local_prover.sp1_prover()
    }

    fn prove<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        opts: ProofOpts,
        context: SP1Context<'a>,
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
        warn_if_not_default(&opts.sp1_prover_opts, &context);
        block_on(self.prove(pk, stdin, opts, kind)).map_err(Into::into)
    }
}

/// Warns if `opts` or `context` are not default values, since they are currently unsupported.
fn warn_if_not_default(opts: &SP1ProverOpts, context: &SP1Context) {
    let _guard = tracing::warn_span!("network_prover").entered();
    if opts != &SP1ProverOpts::default() {
        tracing::warn!("non-default opts will be ignored: {:?}", opts.core_opts);
        tracing::warn!("custom SP1ProverOpts are currently unsupported by the network prover");
    }
    // Exhaustive match is done to ensure we update the warnings if the types change.
    let SP1Context { hook_registry, subproof_verifier, .. } = context;
    if hook_registry.is_some() {
        tracing::warn!("non-default context.hook_registry will be ignored: {:?}", hook_registry);
        tracing::warn!("custom runtime hooks are currently unsupported by the network prover");
        tracing::warn!("proving may fail due to missing hooks");
    }
    if subproof_verifier.is_some() {
        tracing::warn!("non-default context.subproof_verifier will be ignored");
        tracing::warn!("custom subproof verifiers are currently unsupported by the network prover");
    }
}

impl From<SP1ProofKind> for ProofMode {
    fn from(value: SP1ProofKind) -> Self {
        match value {
            SP1ProofKind::Core => Self::Core,
            SP1ProofKind::Compressed => Self::Compressed,
            SP1ProofKind::Plonk => Self::Plonk,
            SP1ProofKind::Groth16 => Self::Groth16,
        }
    }
}

/// Execute an async operation with exponential backoff retries.
pub async fn with_retry<T, F, Fut>(
    operation: F,
    timeout_secs: u64,
    operation_name: &str,
) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let timeout = Duration::from_secs(timeout_secs);
    let backoff = ExponentialBackoff {
        initial_interval: Duration::from_secs(1),
        max_interval: Duration::from_secs(120),
        max_elapsed_time: Some(timeout),
        ..Default::default()
    };

    retry(backoff, || async {
        match operation().await {
            Ok(result) => Ok(result),
            Err(e) => {
                // Check for tonic status errors.
                if let Some(status) = e.downcast_ref::<tonic::Status>() {
                    match status.code() {
                        Code::Unavailable => {
                            log::warn!(
                                "Network temporarily unavailable when {} due to {}, retrying...",
                                operation_name,
                                status.message(),
                            );
                            Err(BackoffError::transient(e))
                        }
                        Code::NotFound => {
                            log::error!(
                                "{} not found due to {}",
                                operation_name,
                                status.message(),
                            );
                            Err(BackoffError::permanent(e))
                        }
                        _ => {
                            log::error!(
                                "Permanent error encountered when {}: {} ({})",
                                operation_name,
                                status.message(),
                                status.code()
                            );
                            Err(BackoffError::permanent(e))
                        }
                    }
                } else {
                    // Check for common transport errors.
                    let error_msg = e.to_string().to_lowercase();
                    let is_transient = error_msg.contains("tls handshake") ||
                        error_msg.contains("dns error") ||
                        error_msg.contains("connection reset") ||
                        error_msg.contains("broken pipe") ||
                        error_msg.contains("transport error") ||
                        error_msg.contains("failed to lookup");

                    if is_transient {
                        log::warn!(
                            "Transient transport error when {}: {}, retrying...",
                            operation_name,
                            error_msg
                        );
                        Err(BackoffError::transient(e))
                    } else {
                        log::error!("Permanent error when {}: {}", operation_name, error_msg);
                        Err(BackoffError::permanent(e))
                    }
                }
            }
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_core_machine::io::SP1Stdin;

    const TEST_PRIVATE_KEY: &str =
        "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn test_proof_opts_configuration() {
        let opts = ProofOpts {
            timeout: Some(Duration::from_secs(100)),
            cycle_limit: Some(1000),
            fulfillment_strategy: Some(FulfillmentStrategy::Hosted),
            skip_simulation: true,
            ..Default::default()
        };

        assert_eq!(opts.timeout.unwrap().as_secs(), 100);
        assert_eq!(opts.cycle_limit.unwrap(), 1000);
        assert_eq!(opts.fulfillment_strategy.unwrap(), FulfillmentStrategy::Hosted);
        assert!(opts.skip_simulation);
    }

    #[test]
    fn test_proof_opts_defaults() {
        let opts = ProofOpts::default();

        assert_eq!(opts.timeout, None);
        assert_eq!(opts.cycle_limit, None);
        assert_eq!(opts.fulfillment_strategy, None);
        assert!(!opts.skip_simulation);
    }

    #[test]
    fn test_cycle_limit_handling() {
        let prover = NetworkProver::new(TEST_PRIVATE_KEY);
        let dummy_stdin = SP1Stdin::default();
        let dummy_elf = test_artifacts::FIBONACCI_ELF;

        // Test with explicit cycle limit
        let result = prover.get_cycle_limit(dummy_elf, &dummy_stdin, Some(1000), false);
        assert_eq!(result.unwrap(), 1000);

        // Test with simulation disabled, no explicit limit
        let result = prover.get_cycle_limit(dummy_elf, &dummy_stdin, None, true);
        assert_eq!(result.unwrap(), DEFAULT_CYCLE_LIMIT);

        // Test with simulation enabled
        let result = prover.get_cycle_limit(dummy_elf, &dummy_stdin, None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_timeout_clamping() {
        // Test minimum bound
        let timeout_secs = NetworkProver::get_timeout_secs(Some(Duration::from_secs(1)));
        assert_eq!(timeout_secs, MIN_TIMEOUT_SECS);

        // Test maximum bound
        let timeout_secs =
            NetworkProver::get_timeout_secs(Some(Duration::from_secs(MAX_TIMEOUT_SECS + 1000)));
        assert_eq!(timeout_secs, MAX_TIMEOUT_SECS);

        // Test value within bounds
        let valid_timeout = 3600;
        let timeout_secs =
            NetworkProver::get_timeout_secs(Some(Duration::from_secs(valid_timeout)));
        assert_eq!(timeout_secs, valid_timeout);

        // Test default when None
        let timeout_secs = NetworkProver::get_timeout_secs(None);
        assert_eq!(timeout_secs, DEFAULT_TIMEOUT_SECS);
    }
}
