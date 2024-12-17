use std::time::{Duration, Instant};

use crate::network_v2::client::DEFAULT_PROVER_NETWORK_RPC;
use crate::{
    network_v2::client::NetworkClient,
    network_v2::proto::network::{
        ExecutionStatus, FulfillmentStatus, FulfillmentStrategy, ProofMode,
    },
    NetworkProverBuilder, Prover, SP1Context, SP1ProofKind, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1VerifyingKey,
};
use anyhow::Result;
use backoff::{future::retry, Error as BackoffError, ExponentialBackoff};
use serde::de::DeserializeOwned;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{components::DefaultProverComponents, SP1Prover, SP1_CIRCUIT_VERSION};
use sp1_stark::SP1ProverOpts;
use tonic::Code;

use {crate::block_on, tokio::time::sleep};

use crate::provers::{CpuProver, ProofOpts, ProverType};

/// The timeout for a proof request to be fulfilled.
const TIMEOUT_SECS: u64 = 14400;

/// The default cycle limit for a proof request if simulation is skipped.
const DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;

/// An implementation of [crate::ProverClient] that can generate proofs on a remote RPC server.
pub struct NetworkProver {
    client: NetworkClient,
    local_prover: CpuProver,
    skip_simulation: bool,
    strategy: FulfillmentStrategy,
}

impl NetworkProver {
    /// Creates a new [NetworkProver] with the given private key.
    pub fn new(private_key: &str, rpc_url: Option<String>, skip_simulation: bool) -> Self {
        let version = SP1_CIRCUIT_VERSION;
        log::info!("Client circuit version: {}", version);
        let local_prover = CpuProver::new();
        let client = NetworkClient::new(private_key, rpc_url);
        Self { client, local_prover, skip_simulation, strategy: FulfillmentStrategy::Hosted }
    }

    /// Sets the fulfillment strategy for the client. By default, the strategy is set to `Hosted`.
    pub fn with_strategy(&mut self, strategy: FulfillmentStrategy) {
        self.strategy = strategy;
    }

    /// Creates a new network prover builder. See [`NetworkProverBuilder`] for more details.
    pub fn builder() -> NetworkProverBuilder {
        NetworkProverBuilder::default()
    }

    /// Registers a program if it is not already registered.
    pub async fn register_program(&self, vk: &SP1VerifyingKey, elf: &[u8]) -> Result<Vec<u8>> {
        self.client.register_program(vk, elf).await
    }

    /// Get the cycle limit, either by simulating or using the default cycle limit.
    fn get_cycle_limit(&self, elf: &[u8], stdin: &SP1Stdin) -> Result<u64> {
        if !self.skip_simulation {
            let (_, report) =
                self.local_prover.sp1_prover().execute(elf, stdin, Default::default())?;
            let cycles = report.total_instruction_count();
            Ok(cycles)
        } else {
            Ok(DEFAULT_CYCLE_LIMIT)
        }
    }

    /// Requests a proof from the prover network, returning the request ID.
    pub async fn request_proof(
        &self,
        vk_hash: &[u8],
        stdin: &SP1Stdin,
        mode: ProofMode,
        cycle_limit: u64,
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>> {
        // Get the timeout.
        let timeout_secs = timeout.map(|dur| dur.as_secs()).unwrap_or(TIMEOUT_SECS);

        log::info!("Requesting proof with cycle limit: {}", cycle_limit);

        // Request the proof with retries.
        let response = with_retry(
            || async {
                self.client
                    .request_proof(
                        vk_hash,
                        stdin,
                        mode,
                        SP1_CIRCUIT_VERSION,
                        self.strategy,
                        timeout_secs,
                        cycle_limit,
                    )
                    .await
            },
            timeout,
            "requesting proof",
        )
        .await?;

        // Log the request ID and transaction hash.
        let tx_hash_hex = "0x".to_string() + &hex::encode(response.tx_hash);
        let request_id = response.body.unwrap().request_id;
        let request_id_hex = "0x".to_string() + &hex::encode(request_id.clone());
        log::info!("Created request {} in transaction {}", request_id_hex, tx_hash_hex);

        if self.client.rpc_url() == DEFAULT_PROVER_NETWORK_RPC {
            log::info!("View in explorer: https://network.succinct.xyz/request/{}", request_id_hex);
        }

        Ok(request_id)
    }

    /// Waits for a proof to be generated and returns the proof. If a timeout is supplied, the
    /// function will return an error if the proof is not generated within the timeout.
    pub async fn wait_proof<P: DeserializeOwned>(
        &self,
        request_id: &[u8],
        timeout: Option<Duration>,
    ) -> Result<P> {
        let mut is_assigned = false;
        let start_time = Instant::now();

        loop {
            // Calculate the remaining timeout.
            if let Some(timeout) = timeout {
                if start_time.elapsed() > timeout {
                    return Err(anyhow::anyhow!("Proof request timed out."));
                }
            }
            let remaining_timeout = timeout.map(|t| {
                let elapsed = start_time.elapsed();
                if elapsed < t {
                    t - elapsed
                } else {
                    Duration::from_secs(0)
                }
            });

            // Get status with retries.
            let (status, maybe_proof) = with_retry(
                || async { self.client.get_proof_request_status::<P>(request_id).await },
                remaining_timeout,
                "getting proof request status",
            )
            .await?;

            // Check the execution status.
            if status.execution_status == ExecutionStatus::Unexecutable as i32 {
                return Err(anyhow::anyhow!("Proof request is unexecutable"));
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
                    return Err(anyhow::anyhow!("Proof request is unfulfillable"));
                }
                _ => {}
            }

            sleep(Duration::from_secs(2)).await;
        }
    }

    /// Requests a proof from the prover network and waits for it to be generated.
    pub async fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        mode: ProofMode,
        timeout: Option<Duration>,
    ) -> Result<SP1ProofWithPublicValues> {
        let vk_hash = self.register_program(&pk.vk, &pk.elf).await?;
        let cycle_limit = self.get_cycle_limit(&pk.elf, &stdin)?;
        let request_id = self.request_proof(&vk_hash, &stdin, mode, cycle_limit, timeout).await?;
        self.wait_proof(&request_id, timeout).await
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
        local_opts.warn_if_not_default("network");
        block_on(self.prove(pk, stdin, kind.into(), opts.timeout))
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
    timeout: Option<Duration>,
    operation_name: &str,
) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let backoff = ExponentialBackoff {
        initial_interval: Duration::from_secs(1),
        max_interval: Duration::from_secs(120),
        max_elapsed_time: timeout,
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
