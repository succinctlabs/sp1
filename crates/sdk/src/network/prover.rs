//! # Network Prover
//!
//! This module provides an implementation of the [`crate::Prover`] trait that can generate proofs
//! on a remote RPC server.

use std::time::{Duration, Instant};

use super::prove::NetworkProveBuilder;
use crate::{
    cpu::{execute::CpuExecuteBuilder, CpuProver},
    network::{
        client::NetworkClient,
        proto::network::{
            ExecutionStatus, FulfillmentStatus, FulfillmentStrategy, GetProofRequestStatusResponse,
            ProofMode,
        },
        Error, DEFAULT_CYCLE_LIMIT, DEFAULT_GAS_LIMIT, DEFAULT_NETWORK_RPC_URL,
        DEFAULT_TIMEOUT_SECS,
    },
    prover::verify_proof,
    ProofFromNetwork, Prover, SP1ProofMode, SP1ProofWithPublicValues, SP1ProvingKey,
    SP1VerifyingKey,
};
use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, Result};
use sp1_core_executor::{SP1Context, SP1ContextBuilder};
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{components::CpuProverComponents, HashableKey, SP1Prover, SP1_CIRCUIT_VERSION};

use crate::network::tee::client::Client as TeeClient;

use crate::utils::block_on;
use tokio::time::sleep;

/// An implementation of [`crate::ProverClient`] that can generate proofs on a remote RPC server.
pub struct NetworkProver {
    pub(crate) client: NetworkClient,
    pub(crate) prover: CpuProver,
    pub(crate) tee_signers: Vec<Address>,
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
        Self { client, prover, tee_signers: vec![] }
    }

    /// Sets the list of TEE signers, used for verifying TEE proofs.
    #[must_use]
    pub fn with_tee_signers(mut self, tee_signers: Vec<Address>) -> Self {
        self.tee_signers = tee_signers;

        self
    }

    /// Get the credit balance of your account on the prover network.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let client = ProverClient::builder().network().build();
    ///     let balance = client.get_balance().await.unwrap();
    /// })
    /// ```
    pub async fn get_balance(&self) -> Result<U256> {
        self.client.get_balance().await
    }

    /// Creates a new [`CpuExecuteBuilder`] for simulating the execution of a program on the CPU.
    ///
    /// # Details
    /// Note that this does not use the network in any capacity. The method is provided for
    /// convenience.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (public_values, execution_report) = client.execute(elf, &stdin).run().unwrap();
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
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
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
            tee_2fa: false,
            min_auction_period: 0,
            whitelist: vec![],
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
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
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
    /// use sp1_sdk::{network::B256, ProverClient};
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
        let (status, maybe_proof): (GetProofRequestStatusResponse, Option<ProofFromNetwork>) =
            self.client.get_proof_request_status(request_id, None).await?;
        let maybe_proof = maybe_proof.map(Into::into);
        Ok((status, maybe_proof))
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
    /// use sp1_sdk::{network::B256, ProverClient};
    ///
    /// tokio_test::block_on(async {
    ///     let request_id = B256::from_slice(&vec![1u8; 32]);
    ///     let client = ProverClient::builder().network().build();
    ///     let (maybe_proof, fulfillment_status) =
    ///         client.process_proof_status(request_id, None).await.unwrap();
    /// })
    /// ```
    pub async fn process_proof_status(
        &self,
        request_id: B256,
        remaining_timeout: Option<Duration>,
    ) -> Result<(Option<SP1ProofWithPublicValues>, FulfillmentStatus)> {
        // Get the status.
        let (status, maybe_proof): (GetProofRequestStatusResponse, Option<ProofFromNetwork>) =
            self.client.get_proof_request_status(request_id, remaining_timeout).await?;

        let maybe_proof = maybe_proof.map(Into::into);

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
    /// * `min_auction_period`: The minimum auction period for the proof request in seconds.
    /// * `whitelist`: The auction whitelist for the proof request.
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
        min_auction_period: u64,
        whitelist: Vec<Address>,
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

        if strategy == FulfillmentStrategy::Auction {
            tracing::info!("├─ Minimum auction period: {:?}", min_auction_period);
            tracing::info!("├─ Whitelist: {:?}", whitelist);
        }

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
                min_auction_period,
                whitelist,
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
        min_auction_period: u64,
        whitelist: Vec<Address>,
    ) -> Result<B256> {
        let vk_hash = self.register_program(&pk.vk, &pk.elf).await?;
        let (cycle_limit, gas_limit) =
            self.get_execution_limits(cycle_limit, gas_limit, &pk.elf, stdin, skip_simulation)?;
        self.request_proof(
            vk_hash,
            stdin,
            mode.into(),
            strategy,
            cycle_limit,
            gas_limit,
            timeout,
            min_auction_period,
            whitelist,
        )
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
        tee_2fa: bool,
        min_auction_period: u64,
        whitelist: Vec<Address>,
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
                min_auction_period,
                whitelist,
            )
            .await?;

        // If 2FA is enabled, spawn a task to get the tee proof.
        // Note: We only support one type of TEE proof for now.

        let handle = if tee_2fa {
            let request = super::tee::api::TEERequest::new(
                &self.client.signer,
                *request_id,
                pk.elf.clone(),
                stdin.clone(),
                cycle_limit.unwrap_or(DEFAULT_CYCLE_LIMIT),
            );

            Some(tokio::spawn(async move {
                let tee_client = TeeClient::default();

                tee_client.execute(request).await
            }))
        } else {
            None
        };

        // Wait for the proof to be generated.
        #[allow(unused_mut)]
        let mut proof = self.wait_proof(request_id, timeout).await?;

        // If 2FA is enabled, wait for the tee proof to be generated and add it to the proof.
        if let Some(handle) = handle {
            let tee_proof = handle
                .await
                .context("Spawning a new task to get the tee proof failed")?
                .context("Error response from TEE server")?;

            proof.tee_proof = Some(tee_proof.as_prefix_bytes());

            return Ok(proof);
        }

        Ok(proof)
    }

    /// The cycle limit and gas limit are determined according to the following priority:
    ///
    /// 1. If either of the limits are explicitly set by the requester, use the specified value.
    /// 2. If simulation is enabled, calculate the limits by simulating the execution of the
    ///    program. This is the default behavior.
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

        let (_, _, report) = execute_result;

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
            false,
            0,
            vec![],
        ))
    }

    fn verify(
        &self,
        bundle: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), crate::SP1VerificationError> {
        if let Some(tee_proof) = &bundle.tee_proof {
            if self.tee_signers.is_empty() {
                return Err(crate::SP1VerificationError::Other(anyhow::anyhow!(
                    "TEE integrity proof verification is enabled, but no TEE signers are provided"
                )));
            }

            let mut bytes = Vec::new();

            // Push the version hash.
            let version_hash =
                alloy_primitives::keccak256(crate::network::tee::SP1_TEE_VERSION.to_le_bytes());
            bytes.extend_from_slice(version_hash.as_ref());

            // Push the vkey.
            bytes.extend_from_slice(&vkey.bytes32_raw());

            // Push the public values hash.
            let public_values_hash = alloy_primitives::keccak256(&bundle.public_values);
            bytes.extend_from_slice(public_values_hash.as_ref());

            // Compute the message digest.
            let message_digest = alloy_primitives::keccak256(&bytes);

            // Parse the signature.
            let signature = k256::ecdsa::Signature::from_bytes(tee_proof[5..69].into())
                .expect("Invalid signature");
            // The recovery id is the last byte of the signature minus 27.
            let recovery_id =
                k256::ecdsa::RecoveryId::from_byte(tee_proof[4] - 27).expect("Invalid recovery id");

            // Recover the signer.
            let signer = k256::ecdsa::VerifyingKey::recover_from_prehash(
                message_digest.as_ref(),
                &signature,
                recovery_id,
            )
            .unwrap();
            let address = alloy_primitives::Address::from_public_key(&signer);

            // Verify the proof.
            if self.tee_signers.contains(&address) {
                verify_proof(self.prover.inner(), self.version(), bundle, vkey)
            } else {
                Err(crate::SP1VerificationError::Other(anyhow::anyhow!(
                    "Invalid TEE proof, signed by unknown address {}",
                    address
                )))
            }
        } else {
            verify_proof(self.prover.inner(), self.version(), bundle, vkey)
        }
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
