//! # Network Prover
//!
//! This module provides an implementation of the [`crate::Prover`] trait that can generate proofs
//! on a remote RPC server.

use std::time::{Duration, Instant};

use super::proto::network::GetProofRequestStatusResponse;
use super::prove::NetworkProveBuilder;
use super::DEFAULT_CYCLE_LIMIT;
use crate::cpu::execute::CpuExecuteBuilder;
use crate::cpu::CpuProver;
use crate::network::{DEFAULT_PROVER_NETWORK_RPC, DEFAULT_TIMEOUT_SECS};
use crate::{
    network::client::NetworkClient,
    network::proto::network::{ExecutionStatus, FulfillmentStatus, FulfillmentStrategy, ProofMode},
    Prover, SP1ProofMode, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey,
};
use anyhow::Result;
use backoff::{future::retry, Error as BackoffError, ExponentialBackoff};
use serde::de::DeserializeOwned;
use sp1_core_executor::{SP1Context, SP1ContextBuilder};
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{components::CpuProverComponents, SP1Prover, SP1_CIRCUIT_VERSION};
use tonic::Code;

use {crate::utils::block_on, tokio::time::sleep};

/// An implementation of [`crate::ProverClient`] that can generate proofs on a remote RPC server.
pub struct NetworkProver {
    pub(crate) client: NetworkClient,
    pub(crate) prover: CpuProver,
}

impl NetworkProver {
    /// Creates a new [`NetworkProver`] with the given private key.
    ///
    /// # Details
    /// * `private_key`: The Secp256k1 private key to use for signing requests.
    /// * `rpc_url`: The rpc url to use for the prover network.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::NetworkProver;
    ///
    /// let prover = NetworkProver::new("...", "...");
    /// ```
    #[must_use]
    pub fn new(private_key: &str, rpc_url: &str) -> Self {
        let prover = CpuProver::new();
        let client = NetworkClient::new(private_key, rpc_url);
        Self { client, prover }
    }

    /// Creates a new [`CpuExecuteBuilder`] for simulating the execution of a program on the CPU.
    ///
    /// # Details
    /// Note that this does not use the network in any capacity. The method is provided for
    /// convenience.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (public_values, execution_report) = client.execute(elf, &stdin)
    ///     .run()
    ///     .unwrap();
    /// ```
    pub fn execute<'a>(&'a self, elf: &'a [u8], stdin: &SP1Stdin) -> CpuExecuteBuilder<'a> {
        CpuExecuteBuilder {
            prover: self.prover.inner(),
            elf,
            stdin: stdin.clone(),
            context_builder: SP1ContextBuilder::default(),
        }
    }

    /// A request to generate a proof for a given proving key and input.
    ///
    /// # Details
    /// * `pk`: The proving key to use for the proof.
    /// * `stdin`: The input to use for the proof.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().network().build();
    /// let (pk, vk) = client.setup(elf);
    /// let proof = client.prove(&pk, &stdin).run();
    /// ```
    pub fn prove<'a>(
        &'a self,
        pk: &'a SP1ProvingKey,
        stdin: &'a SP1Stdin,
    ) -> NetworkProveBuilder<'a> {
        NetworkProveBuilder {
            prover: self,
            mode: SP1ProofMode::Core,
            pk,
            stdin: stdin.clone(),
            timeout: None,
            strategy: FulfillmentStrategy::Hosted,
            skip_simulation: false,
        }
    }

    /// Registers a program if it is not already registered.
    ///
    /// # Details
    /// * `vk`: The verifying key to use for the program.
    /// * `elf`: The elf to use for the program.
    ///
    /// Note that this method requires that the user honestly registers the program (i.e., the elf
    /// matches the vk).
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let client = ProverClient::builder().network().build();
    /// let (pk, vk) = client.setup(elf);
    ///
    /// let vk_hash = client.register_program(&vk, elf);
    /// ```
    pub async fn register_program(&self, vk: &SP1VerifyingKey, elf: &[u8]) -> Result<Vec<u8>> {
        self.client.register_program(vk, elf).await
    }

    /// Gets the status of a proof request.
    ///
    /// # Details
    /// * `request_id`: The request ID to get the status of.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient}
    ///
    /// let request_id = vec![1u8; 32];
    /// let client = ProverClient::builder().network().build();
    /// let (status, maybe_proof) = client.get_proof_status(&request_id).await?;   
    /// ```
    pub async fn get_proof_status<P: DeserializeOwned>(
        &self,
        request_id: &[u8],
    ) -> Result<(GetProofRequestStatusResponse, Option<P>)> {
        self.client.get_proof_request_status(request_id).await
    }

    /// Requests a proof from the prover network, returning the request ID.
    pub(crate) async fn request_proof(
        &self,
        vk_hash: &[u8],
        stdin: &SP1Stdin,
        mode: ProofMode,
        strategy: FulfillmentStrategy,
        cycle_limit: u64,
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>> {
        // Get the timeout.
        let timeout_secs = timeout.map_or(DEFAULT_TIMEOUT_SECS, |dur| dur.as_secs());

        // Log the request.
        log::info!("Requesting proof:");
        log::info!("├─ Cycle limit: {}", cycle_limit);
        log::info!("├─ Proof mode: {:?}", mode);
        log::info!("├─ Strategy: {:?}", strategy);
        log::info!("├─ Timeout: {} seconds", timeout_secs);
        log::info!("└─ Circuit version: {}", SP1_CIRCUIT_VERSION);

        // Request the proof with retries.
        let response = with_retry(
            || async {
                self.client
                    .request_proof(
                        vk_hash,
                        stdin,
                        mode,
                        SP1_CIRCUIT_VERSION,
                        strategy,
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

        if self.client.rpc_url == DEFAULT_PROVER_NETWORK_RPC {
            log::info!(
                "View request status at: https://network.succinct.xyz/request/{}",
                request_id_hex
            );
        }

        Ok(request_id)
    }

    /// Waits for a proof to be generated and returns the proof. If a timeout is supplied, the
    /// function will return an error if the proof is not generated within the timeout.
    pub(crate) async fn wait_proof<P: DeserializeOwned>(
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
                    return Err(anyhow::anyhow!("proof request timed out."));
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
                return Err(anyhow::anyhow!("proof request is unexecutable"));
            }

            // Check the fulfillment status.
            match FulfillmentStatus::try_from(status.fulfillment_status) {
                Ok(FulfillmentStatus::Fulfilled) => {
                    return Ok(maybe_proof.unwrap());
                }
                Ok(FulfillmentStatus::Assigned) => {
                    if !is_assigned {
                        log::info!("proof request assigned, proving...");
                        is_assigned = true;
                    }
                }
                Ok(FulfillmentStatus::Unfulfillable) => {
                    return Err(anyhow::anyhow!("proof request is unfulfillable"));
                }
                _ => {}
            }

            sleep(Duration::from_secs(2)).await;
        }
    }

    /// Requests a proof from the prover network.
    pub(crate) async fn request_proof_impl(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
        strategy: FulfillmentStrategy,
        timeout: Option<Duration>,
        skip_simulation: bool,
    ) -> Result<Vec<u8>> {
        let vk_hash = self.register_program(&pk.vk, &pk.elf).await?;
        let cycle_limit = self.get_cycle_limit(&pk.elf, stdin, skip_simulation)?;
        self.request_proof(&vk_hash, stdin, mode, strategy, cycle_limit, timeout).await
    }

    /// Requests a proof from the prover network and waits for it to be generated.
    pub(crate) async fn prove_impl(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
        strategy: FulfillmentStrategy,
        timeout: Option<Duration>,
        skip_simulation: bool,
    ) -> Result<SP1ProofWithPublicValues> {
        let request_id = self
            .request_proof_impl(pk, stdin, mode, strategy, timeout, skip_simulation)
            .await?;
        self.wait_proof(&request_id, timeout).await
    }

    fn get_cycle_limit(&self, elf: &[u8], stdin: &SP1Stdin, skip_simulation: bool) -> Result<u64> {
        if skip_simulation {
            Ok(DEFAULT_CYCLE_LIMIT)
        } else {
            let (_, report) = self.prover.inner().execute(elf, stdin, SP1Context::default())?;
            let cycles = report.total_instruction_count();
            Ok(cycles)
        }
    }
}

impl Prover<CpuProverComponents> for NetworkProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn inner(&self) -> &SP1Prover {
        self.prover.inner()
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
    ) -> Result<SP1ProofWithPublicValues> {
        block_on(self.prove_impl(pk, stdin, mode, FulfillmentStrategy::Hosted, None, false))
    }
}

impl From<SP1ProofMode> for ProofMode {
    fn from(value: SP1ProofMode) -> Self {
        match value {
            SP1ProofMode::Core => Self::Core,
            SP1ProofMode::Compressed => Self::Compressed,
            SP1ProofMode::Plonk => Self::Plonk,
            SP1ProofMode::Groth16 => Self::Groth16,
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
