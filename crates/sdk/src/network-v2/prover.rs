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

/// The default proof mode to use for proof requests.
pub const DEFAULT_PROOF_MODE: ProofMode = ProofMode::Groth16;

/// The default fulfillment strategy to use for proof requests.
pub const DEFAULT_FULFILLMENT_STRATEGY: FulfillmentStrategy = FulfillmentStrategy::Hosted;

/// The default timeout for a proof request to be fulfilled (4 hours).
pub const DEFAULT_TIMEOUT_SECS: u64 = 14400;

/// Minimum allowed timeout in seconds (10 seconds)
pub const MIN_TIMEOUT_SECS: u64 = 10;

/// Maximum allowed timeout in seconds (24 hours)
pub const MAX_TIMEOUT_SECS: u64 = 86400;

/// The default cycle limit for a proof request if simulation and the cycle limit is not explicitly
/// set.
pub const DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;

/// An implementation of [crate::ProverClient] that can generate proofs on a remote RPC server.
pub struct NetworkProver {
    client: NetworkClient,
    local_prover: CpuProver,
    mode: ProofMode,
    strategy: FulfillmentStrategy,
    timeout_secs: u64,
    cycle_limit: Option<u64>,
    skip_simulation: bool,
}

impl NetworkProver {
    /// Creates a new `NetworkProver` with the given private key.
    pub fn new(private_key: &str) -> Self {
        let version = SP1_CIRCUIT_VERSION;
        log::info!("Client circuit version: {}", version);

        Self {
            client: NetworkClient::new(private_key),
            local_prover: CpuProver::new(),
            mode: DEFAULT_PROOF_MODE,
            strategy: DEFAULT_FULFILLMENT_STRATEGY,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            cycle_limit: None,
            skip_simulation: false,
        }
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

    /// Sets the mode to use for proof requests.
    ///
    /// See `ProofMode` for more details about each mode.
    pub fn with_mode(mut self, mode: ProofMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the fulfillment strategy for proof requests.
    ///
    /// See `FulfillmentStrategy` for more details about each strategy.
    pub fn with_strategy(mut self, strategy: FulfillmentStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Sets the timeout for proof requests. The network will ignore any requests that take longer
    /// than this timeout.
    ///
    /// Additionally, the `NetworkProver` will stop polling for the proof request status when this
    /// timeout is reached.
    ///
    /// The timeout will be clamped between MIN_TIMEOUT_SECS and MAX_TIMEOUT_SECS.
    /// If not set, the default timeout (DEFAULT_TIMEOUT_SECS) will be used.
    pub fn with_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs.clamp(MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS);
        self
    }

    /// Sets a fixed cycle limit for proof requests. The request fails if the cycles used exceed
    /// this limit.
    ///
    /// When set, this value will always be used as the cycle limit, regardless of the
    /// `skip_simulation` setting.
    ///
    /// If this is not set:
    /// - The cycle limit will be calculated by simulating the program (if simulation is enabled)
    /// - The default cycle limit will be used (if simulation is disabled via `skip_simulation()`)
    ///
    /// In the case that cycle limit is greater than the cycles used, a refund will be issued.
    pub fn with_cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.cycle_limit = Some(cycle_limit);
        self
    }

    /// Disables simulation for cycle limit calculation.
    ///
    /// This is useful if program execution requires significant computation, and you already have
    /// an expected cycle count you can use with `with_cycle_limit()`.
    ///
    /// When simulation is disabled:
    /// - If a cycle limit was set via `with_cycle_limit()`, that value will be used
    /// - Otherwise, the default cycle limit will be used
    pub fn skip_simulation(mut self) -> Self {
        self.skip_simulation = true;
        self
    }

    /// Creates a new network prover builder. See [`NetworkProverBuilder`] for more details.
    pub fn builder() -> NetworkProverBuilder {
        NetworkProverBuilder::default()
    }

    /// Gets the mode to use for a proof request.
    fn get_mode(&self) -> ProofMode {
        self.mode
    }

    /// Gets the fulfillment strategy to use for a proof request.
    fn get_strategy(&self) -> FulfillmentStrategy {
        self.strategy
    }

    /// Gets the configured timeout in seconds to use for a proof request.
    fn get_timeout_secs(&self) -> u64 {
        self.timeout_secs
    }

    /// Get the cycle limit to used for a proof request.
    ///
    /// The cycle limit is determined according to the following rules:
    /// - If a cycle limit was explicitly set, use that
    /// - If simulation is enabled (default), calculate limit by simulating
    /// - Otherwise use the default cycle limit
    fn get_cycle_limit(&self, elf: &[u8], stdin: &SP1Stdin) -> Result<u64, Error> {
        // If cycle_limit was explicitly set via with_cycle_limit(), always use that
        if let Some(limit) = self.cycle_limit {
            return Ok(limit);
        }

        // If simulation is enabled (default), simulate to get the limit.
        if !self.skip_simulation {
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
                return Err(Error::RequestTimedOut);
            }
            let remaining_timeout = timeout.saturating_sub(start_time.elapsed());

            // Get the status with retries.
            let (status, maybe_proof) = with_retry(
                || async { self.client.get_proof_request_status(request_id).await },
                remaining_timeout.as_secs(),
                "getting proof status",
            )
            .await?;

            // Check the execution status.
            if status.execution_status == ExecutionStatus::Unexecutable as i32 {
                return Err(Error::RequestUnexecutable);
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
                    return Err(Error::RequestUnfulfillable);
                }
                _ => {}
            }

            sleep(Duration::from_secs(2)).await;
        }
    }

    /// Requests a proof from the prover network and waits for it to be returned.
    pub async fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
    ) -> Result<SP1ProofWithPublicValues, Error> {
        // Ensure the program is registered.
        let vk_hash = self.register_program(&pk.vk, &pk.elf).await?;

        // Get the configured settings.
        let version = SP1_CIRCUIT_VERSION;
        let mode = self.get_mode();
        let strategy = self.get_strategy();
        let timeout_secs = self.get_timeout_secs();
        let cycle_limit = self.get_cycle_limit(&pk.elf, &stdin)?;

        // Request the proof.
        let request_id = self
            .request_proof(&vk_hash, &stdin, version, mode, strategy, timeout_secs, cycle_limit)
            .await?;

        // Wait for the proof to be generated.
        self.wait_proof(&request_id, timeout_secs).await
    }

    /// Note: It is recommended to use NetworkProver::prove() with builder methods instead.
    fn prove_with_config<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        opts: ProofOpts,
        context: SP1Context<'a>,
        _kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
        warn_if_not_default(&opts.sp1_prover_opts, &context);
        block_on(self.prove(pk, stdin)).map_err(Into::into)
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
        self.prove_with_config(pk, stdin, opts, context, kind)
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

    const TEST_PRIVATE_KEY: &str =
        "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn test_builder_pattern() {
        let prover = NetworkProver::new(TEST_PRIVATE_KEY)
            .with_timeout_secs(100)
            .with_cycle_limit(1000)
            .with_mode(ProofMode::Core)
            .with_strategy(FulfillmentStrategy::Hosted)
            .skip_simulation();

        assert_eq!(prover.timeout_secs, 100);
        assert_eq!(prover.cycle_limit, Some(1000));
        assert_eq!(prover.mode, ProofMode::Core);
        assert_eq!(prover.strategy, FulfillmentStrategy::Hosted);
        assert!(prover.skip_simulation);
    }

    #[test]
    fn test_timeout_bounds() {
        // Test minimum bound
        let prover = NetworkProver::new(TEST_PRIVATE_KEY).with_timeout_secs(1);
        assert_eq!(prover.timeout_secs, MIN_TIMEOUT_SECS);

        // Test maximum bound
        let prover =
            NetworkProver::new(TEST_PRIVATE_KEY).with_timeout_secs(MAX_TIMEOUT_SECS + 1000);
        assert_eq!(prover.timeout_secs, MAX_TIMEOUT_SECS);

        // Test value within bounds
        let valid_timeout = 3600; // 1 hour
        let prover = NetworkProver::new(TEST_PRIVATE_KEY).with_timeout_secs(valid_timeout);
        assert_eq!(prover.timeout_secs, valid_timeout);
    }

    #[test]
    fn test_default_values() {
        let prover = NetworkProver::new(TEST_PRIVATE_KEY);

        assert_eq!(prover.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert_eq!(prover.mode, ProofMode::Core);
        assert_eq!(prover.strategy, FulfillmentStrategy::Hosted);
        assert_eq!(prover.cycle_limit, None);
        assert!(!prover.skip_simulation);
    }

    #[test]
    fn test_cycle_limit_handling() {
        let prover = NetworkProver::new(TEST_PRIVATE_KEY);
        let dummy_stdin = SP1Stdin::new();
        let elf = test_artifacts::FIBONACCI_ELF;

        // Test with simulation enabled (default)
        let limit = prover.get_cycle_limit(elf, &dummy_stdin).unwrap();
        assert!(limit > 0);

        // Test with simulation disabled
        let prover = prover.skip_simulation();
        assert_eq!(prover.get_cycle_limit(elf, &dummy_stdin).unwrap(), DEFAULT_CYCLE_LIMIT);

        // Test with explicit cycle limit
        let explicit_limit = 1000;
        let prover = prover.with_cycle_limit(explicit_limit);
        assert_eq!(prover.get_cycle_limit(elf, &dummy_stdin).unwrap(), explicit_limit);
    }
}
