//! # Network Prover
//!
//! This module provides an implementation of the [`crate::Prover`] trait that can generate proofs
//! on a remote RPC server.

use std::time::{Duration, Instant};

use super::prove::NetworkProveBuilder;
use crate::cpu::execute::CpuExecuteBuilder;
use crate::cpu::CpuProver;
use crate::network::proto::network::GetProofRequestStatusResponse;
use crate::network::{
    Error, DEFAULT_CYCLE_LIMIT, DEFAULT_GAS_LIMIT, DEFAULT_NETWORK_RPC_URL, DEFAULT_TIMEOUT_SECS,
};
use crate::{
    network::client::NetworkClient,
    network::proto::network::{ExecutionStatus, FulfillmentStatus, FulfillmentStrategy, ProofMode},
    Prover, SP1ProofMode, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey,
};
use alloy_primitives::B256;
use anyhow::Result;
use sp1_core_executor::{SP1Context, SP1ContextBuilder};
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{components::CpuProverComponents, SP1Prover, SP1_CIRCUIT_VERSION};

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
            cycle_limit: None,
            gas_limit: None,
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
    pub async fn register_program(&self, vk: &SP1VerifyingKey, elf: &[u8]) -> Result<B256> {
        self.client.register_program(vk, elf).await
    }

    /// Gets the status of a proof request. Re-exposes the status response from the client.
    ///
    /// # Details
    /// * `request_id`: The request ID to get the status of.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, network::B256};
    ///
    /// tokio_test::block_on(async {
    ///     let request_id = B256::from_slice(&vec![1u8; 32]);
    ///     let client = ProverClient::builder().network().build();
    ///     let (status, maybe_proof) = client.get_proof_status(request_id).await.unwrap();   
    /// })
    /// ```
    pub async fn get_proof_status(
        &self,
        request_id: B256,
    ) -> Result<(GetProofRequestStatusResponse, Option<SP1ProofWithPublicValues>)> {
        self.client.get_proof_request_status(request_id, None).await
    }

    /// Gets the status of a proof request with handling for timeouts and unfulfillable requests.
    ///
    /// Returns the proof if it is fulfilled and the fulfillment status. Handles statuses indicating
    /// that the proof is unfulfillable or unexecutable with errors.
    ///
    /// # Details
    /// * `request_id`: The request ID to get the status of.
    /// * `remaining_timeout`: The remaining timeout for the proof request.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, network::B256};
    ///
    /// tokio_test::block_on(async {
    ///     let request_id = B256::from_slice(&vec![1u8; 32]);
    ///     let client = ProverClient::builder().network().build();
    ///     let (maybe_proof, fulfillment_status) = client.process_proof_status(request_id, None).await.unwrap();   
    /// })
    /// ```
    pub async fn process_proof_status(
        &self,
        request_id: B256,
        remaining_timeout: Option<Duration>,
    ) -> Result<(Option<SP1ProofWithPublicValues>, FulfillmentStatus)> {
        // Get the status.
        let (status, maybe_proof): (
            GetProofRequestStatusResponse,
            Option<SP1ProofWithPublicValues>,
        ) = self.client.get_proof_request_status(request_id, remaining_timeout).await?;

        // Check if current time exceeds deadline. If so, the proof has timed out.
        let current_time =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        if current_time > status.deadline {
            return Err(Error::RequestTimedOut { request_id: request_id.to_vec() }.into());
        }

        // Get the execution and fulfillment statuses.
        let execution_status = ExecutionStatus::try_from(status.execution_status).unwrap();
        let fulfillment_status = FulfillmentStatus::try_from(status.fulfillment_status).unwrap();

        // Check the execution status.
        if execution_status == ExecutionStatus::Unexecutable {
            return Err(Error::RequestUnexecutable { request_id: request_id.to_vec() }.into());
        }

        // Check the fulfillment status.
        if fulfillment_status == FulfillmentStatus::Fulfilled {
            return Ok((maybe_proof, fulfillment_status));
        }
        if fulfillment_status == FulfillmentStatus::Unfulfillable {
            return Err(Error::RequestUnfulfillable { request_id: request_id.to_vec() }.into());
        }

        Ok((None, fulfillment_status))
    }

    /// Requests a proof from the prover network, returning the request ID.
    ///
    /// # Details
    /// * `vk_hash`: The hash of the verifying key to use for the proof.
    /// * `stdin`: The input to use for the proof.
    /// * `mode`: The proof mode to use for the proof.
    /// * `strategy`: The fulfillment strategy to use for the proof.
    /// * `cycle_limit`: The cycle limit to use for the proof.
    /// * `gas_limit`: The gas limit to use for the proof.
    /// * `timeout`: The timeout for the proof request.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn request_proof(
        &self,
        vk_hash: B256,
        stdin: &SP1Stdin,
        mode: ProofMode,
        strategy: FulfillmentStrategy,
        cycle_limit: u64,
        gas_limit: u64,
        timeout: Option<Duration>,
    ) -> Result<B256> {
        // Get the timeout.
        let timeout_secs = timeout.map_or(DEFAULT_TIMEOUT_SECS, |dur| dur.as_secs());

        // Log the request.
        tracing::info!("Requesting proof:");
        tracing::info!("├─ Cycle limit: {}", cycle_limit);
        tracing::info!("├─ Gas limit: {}", gas_limit);
        tracing::info!("├─ Proof mode: {:?}", mode);
        tracing::info!("├─ Strategy: {:?}", strategy);
        tracing::info!("├─ Timeout: {} seconds", timeout_secs);
        tracing::info!("└─ Circuit version: {}", SP1_CIRCUIT_VERSION);

        // Request the proof.
        let response = self
            .client
            .request_proof(
                vk_hash,
                stdin,
                mode,
                SP1_CIRCUIT_VERSION,
                strategy,
                timeout_secs,
                cycle_limit,
                gas_limit,
            )
            .await?;

        // Log the request ID and transaction hash.
        let tx_hash = B256::from_slice(&response.tx_hash);
        let request_id = B256::from_slice(&response.body.unwrap().request_id);
        tracing::info!("Created request {} in transaction {:?}", request_id, tx_hash);

        if self.client.rpc_url == DEFAULT_NETWORK_RPC_URL {
            tracing::info!(
                "View request status at: https://network.succinct.xyz/request/{}",
                request_id
            );
        }

        Ok(request_id)
    }

    /// Waits for a proof to be generated and returns the proof. If a timeout is supplied, the
    /// function will return an error if the proof is not generated within the timeout.
    pub async fn wait_proof(
        &self,
        request_id: B256,
        timeout: Option<Duration>,
    ) -> Result<SP1ProofWithPublicValues> {
        let mut is_assigned = false;
        let start_time = Instant::now();

        loop {
            // Calculate the remaining timeout.
            if let Some(timeout) = timeout {
                if start_time.elapsed() > timeout {
                    return Err(Error::RequestTimedOut { request_id: request_id.to_vec() }.into());
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

            let (maybe_proof, fulfillment_status) =
                self.process_proof_status(request_id, remaining_timeout).await?;

            if fulfillment_status == FulfillmentStatus::Fulfilled {
                return Ok(maybe_proof.unwrap());
            } else if fulfillment_status == FulfillmentStatus::Assigned && !is_assigned {
                tracing::info!("Proof request assigned, proving...");
                is_assigned = true;
            }

            sleep(Duration::from_secs(2)).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn request_proof_impl(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
        strategy: FulfillmentStrategy,
        timeout: Option<Duration>,
        skip_simulation: bool,
        cycle_limit: Option<u64>,
        gas_limit: Option<u64>,
    ) -> Result<B256> {
        let vk_hash = self.register_program(&pk.vk, &pk.elf).await?;
        let (cycle_limit, gas_limit) =
            self.get_execution_limits(cycle_limit, gas_limit, &pk.elf, stdin, skip_simulation)?;
        self.request_proof(vk_hash, stdin, mode.into(), strategy, cycle_limit, gas_limit, timeout)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn prove_impl(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
        strategy: FulfillmentStrategy,
        timeout: Option<Duration>,
        skip_simulation: bool,
        cycle_limit: Option<u64>,
        gas_limit: Option<u64>,
    ) -> Result<SP1ProofWithPublicValues> {
        let request_id = self
            .request_proof_impl(
                pk,
                stdin,
                mode,
                strategy,
                timeout,
                skip_simulation,
                cycle_limit,
                gas_limit,
            )
            .await?;
        self.wait_proof(request_id, timeout).await
    }

    /// The cycle limit and gas limit are determined according to the following priority:
    ///
    /// 1. If either of the limits are explicitly set by the requester, use the specified value.
    /// 2. If simulation is enabled, calculate the limits by simulating the
    ///    execution of the program. This is the default behavior.
    /// 3. Otherwise, use the default limits ([`DEFAULT_CYCLE_LIMIT`] and [`DEFAULT_GAS_LIMIT`]).
    fn get_execution_limits(
        &self,
        cycle_limit: Option<u64>,
        gas_limit: Option<u64>,
        elf: &[u8],
        stdin: &SP1Stdin,
        skip_simulation: bool,
    ) -> Result<(u64, u64)> {
        let cycle_limit_value = if let Some(cycles) = cycle_limit {
            cycles
        } else if skip_simulation {
            DEFAULT_CYCLE_LIMIT
        } else {
            // Will be calculated through simulation.
            0
        };

        let gas_limit_value = if let Some(gas) = gas_limit {
            gas
        } else if skip_simulation {
            DEFAULT_GAS_LIMIT
        } else {
            // Will be calculated through simulation.
            0
        };

        // If both limits were explicitly provided or skip_simulation is true, return immediately.
        if (cycle_limit.is_some() && gas_limit.is_some()) || skip_simulation {
            return Ok((cycle_limit_value, gas_limit_value));
        }

        // One of the limits were not provided and simulation is not skipped, so simulate to get one
        // or both limits
        let execute_result = self
            .prover
            .inner()
            .execute(elf, stdin, SP1Context::builder().calculate_gas(true).build())
            .map_err(|_| Error::SimulationFailed)?;

        let (_, report) = execute_result;

        // Use simulated values for the ones that are not explicitly provided.
        let final_cycle_limit = if cycle_limit.is_none() {
            report.total_instruction_count()
        } else {
            cycle_limit_value
        };
        let final_gas_limit = if gas_limit.is_none() {
            report.gas.unwrap_or(DEFAULT_GAS_LIMIT)
        } else {
            gas_limit_value
        };

        Ok((final_cycle_limit, final_gas_limit))
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
        block_on(self.prove_impl(
            pk,
            stdin,
            mode,
            FulfillmentStrategy::Hosted,
            None,
            false,
            None,
            None,
        ))
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
