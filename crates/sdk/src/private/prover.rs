use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use anyhow::Result;
use sp1_core_executor::SP1ContextBuilder;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{
    components::CpuProverComponents, SP1Prover, SP1ProvingKey, SP1VerifyingKey, SP1_CIRCUIT_VERSION,
};
use tokio::time::sleep;

use crate::{
    cpu::execute::CpuExecuteBuilder,
    network::{
        proto::types::FulfillmentStatus, utils::calculate_timeout_from_gas_limit, Error,
        PRIVATE_EXPLORER_URL, PUBLIC_EXPLORER_URL,
    },
    private::{client::PrivateClient, prove::PrivateProveBuilder},
    utils::block_on,
    CpuProver, ProofFromNetwork, Prover, SP1ProofMode, SP1ProofWithPublicValues,
};

pub struct PrivateProver {
    pub(crate) client: PrivateClient,
    pub(crate) prover: CpuProver,
}

impl PrivateProver {
    pub fn new(private_key: impl ToString, rpc_url: impl ToString) -> Self {
        let client = PrivateClient::new(private_key, rpc_url);
        PrivateProver { client, prover: CpuProver::new() }
    }

    /// Creates a new [`CpuExecuteBuilder`] for simulating the execution of a program on the CPU.
    ///
    /// # Details
    /// Note that this does not use the private infratructure in any capacity. The program
    /// is executed locally.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().private().build();
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
    /// let client = ProverClient::builder().private().build();
    /// let (pk, vk) = client.setup(elf);
    /// let proof = client.prove(&pk, &stdin).run();
    /// ```
    pub fn prove<'a>(
        &'a self,
        pk: &'a SP1ProvingKey,
        stdin: &'a SP1Stdin,
    ) -> PrivateProveBuilder<'a> {
        PrivateProveBuilder {
            prover: self,
            mode: SP1ProofMode::Core,
            pk,
            stdin: stdin.clone(),
            timeout: None,
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
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let client = ProverClient::builder().network().build();
    /// let (pk, vk) = client.setup(elf);
    ///
    /// let vk_hash = client.register_program(&vk, elf);
    /// ```
    pub async fn register_program(&self, pk: &SP1ProvingKey) -> Result<B256> {
        self.client.register_program(pk).await
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
    ///     let client = ProverClient::builder().private().build();
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
        let response = self.client.get_proof_request_status(request_id, remaining_timeout).await?;

        // Check if current time exceeds deadline. If so, the proof has timed out.
        let current_time =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        if current_time > response.deadline {
            return Err(Error::RequestTimedOut { request_id: request_id.to_vec() }.into());
        }

        // Check the fulfillment status.
        if response.fulfillment_status == FulfillmentStatus::Fulfilled {
            return Ok((response.proof.and_then(Arc::into_inner), response.fulfillment_status));
        }
        if response.fulfillment_status == FulfillmentStatus::Unfulfillable {
            return Err(Error::RequestUnfulfillable { request_id: request_id.to_vec() }.into());
        }

        Ok((None, response.fulfillment_status))
    }

    pub(crate) async fn request_proof(
        &self,
        vk_hash: B256,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
        cycle_limit: u64,
        gas_limit: u64,
        timeout: Option<Duration>,
    ) -> Result<B256> {
        // Get the timeout. If no timeout is specified, auto-calculate based on gas limit.
        let timeout_secs = timeout
            .map_or_else(|| calculate_timeout_from_gas_limit(gas_limit), |dur| dur.as_secs());

        // Log the request.
        tracing::info!("Requesting proof:");
        tracing::info!("├─ Proof mode: {:?}", mode);
        tracing::info!("├─ Circuit version: {}", SP1_CIRCUIT_VERSION);
        tracing::info!("├─ Timeout: {} seconds", timeout_secs);
        tracing::info!("├─ Cycle limit: {} cycles", cycle_limit);
        tracing::info!("└─ Gas limit: {} PGUs", gas_limit);

        // Request the proof.
        let response = self
            .client
            .request_proof(vk_hash, stdin, mode, timeout_secs, cycle_limit, gas_limit)
            .await?;

        // Log the request ID.
        let request_id = B256::from_slice(&response.body.unwrap().request_id);
        tracing::info!("Created request {}", request_id);

        let explorer = match self.client.rpc_url.trim_end_matches('/') {
            DEFAULT_NETWORK_RPC_URL => Some(PUBLIC_EXPLORER_URL),
            PRIVATE_NETWORK_RPC_URL => Some(PRIVATE_EXPLORER_URL),
            _ => None,
        };

        if let Some(base_url) = explorer {
            tracing::info!("View request status at: {}/request/{}", base_url, request_id);
        }

        Ok(request_id)
    }

    /// Waits for a proof to be generated and returns the proof. If a timeout is supplied, the
    /// function will return an error if the proof is not generated within the timeout.
    /// If `auction_timeout` is supplied, the function will return an error if the proof request
    /// remains in "requested" status for longer than the auction timeout.
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

    pub(crate) async fn request_proof_impl(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
        timeout: Option<Duration>,
        skip_simulation: bool,
        cycle_limit: Option<u64>,
        gas_limit: Option<u64>,
    ) -> Result<B256> {
        let vk_hash = self.register_program(&pk).await?;
        let (cycle_limit, gas_limit, public_values_hash) = crate::utils::get_execution_limits(
            self.prover.inner(),
            cycle_limit,
            gas_limit,
            &pk.elf,
            stdin,
            skip_simulation,
        )?;

        self.request_proof(vk_hash, stdin, mode.into(), cycle_limit, gas_limit, timeout).await
    }

    pub(crate) async fn prove_impl(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
        timeout: Option<Duration>,
        skip_simulation: bool,
        cycle_limit: Option<u64>,
        gas_limit: Option<u64>,
    ) -> Result<SP1ProofWithPublicValues> {
        let request_id = self
            .request_proof_impl(pk, stdin, mode, timeout, skip_simulation, cycle_limit, gas_limit)
            .await?;

        // Wait for the proof to be generated.
        let proof = self.wait_proof(request_id, timeout).await?;

        Ok(proof)
    }
}

impl Prover<CpuProverComponents> for PrivateProver {
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
        block_on(self.prove_impl(pk, stdin, mode, None, false, None, None))
    }

    fn verify(
        &self,
        bundle: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), crate::SP1VerificationError> {
        todo!()
    }
}
