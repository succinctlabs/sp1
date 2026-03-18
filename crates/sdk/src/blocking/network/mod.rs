//! # SP1 Network Prover (Blocking)
//!
//! A blocking wrapper around the async [`crate::network::prover::NetworkProver`] that can generate
//! proofs on a remote RPC server.

pub mod builder;
pub mod prove;

use std::time::Duration;

use alloy_primitives::{B256, U256};
use anyhow::Result;
use prove::NetworkProveBuilder;
use sp1_core_executor::StatusCode;
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::Elf;
use sp1_prover::{worker::SP1NodeCore, SP1VerifyingKey};

use crate::{
    blocking::prover::Prover,
    network::{
        proto::{
            types::{FulfillmentStrategy, ProofRequest},
            GetProofRequestParamsResponse, GetProofRequestStatusResponse,
        },
        NetworkMode,
    },
    SP1ProofMode, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerificationError,
};

/// A blocking implementation of the network prover that can generate proofs on a remote RPC server.
#[derive(Clone)]
pub struct NetworkProver {
    pub(crate) prover: crate::network::prover::NetworkProver,
}

impl Prover for NetworkProver {
    type ProvingKey = SP1ProvingKey;
    type Error = anyhow::Error;
    type ProveRequest<'a> = NetworkProveBuilder<'a>;

    fn inner(&self) -> &SP1NodeCore {
        self.prover.node.inner()
    }

    fn setup(&self, elf: Elf) -> Result<Self::ProvingKey, Self::Error> {
        crate::blocking::block_on(async {
            let vk = self.prover.node.setup(&elf).await?;
            Ok(SP1ProvingKey { vk, elf })
        })
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        let strategy = self.prover.default_fulfillment_strategy();

        NetworkProveBuilder {
            base: crate::blocking::prover::BaseProveRequest::new(self, pk, stdin),
            timeout: None,
            strategy,
            skip_simulation: false,
            cycle_limit: None,
            gas_limit: None,
            tee_2fa: false,
            min_auction_period: 0,
            whitelist: None,
            auctioneer: None,
            executor: None,
            verifier: None,
            treasury: None,
            max_price_per_pgu: None,
            auction_timeout: None,
        }
    }

    fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
        status_code: Option<StatusCode>,
    ) -> Result<(), SP1VerificationError> {
        crate::Prover::verify(&self.prover, proof, vkey, status_code)
    }
}

impl NetworkProver {
    /// Gets the network mode of this prover.
    #[must_use]
    pub fn network_mode(&self) -> NetworkMode {
        self.prover.network_mode()
    }

    /// Gets the default fulfillment strategy for this prover's network mode.
    #[must_use]
    pub fn default_fulfillment_strategy(&self) -> FulfillmentStrategy {
        self.prover.default_fulfillment_strategy()
    }

    /// Get the credit balance of your account on the prover network.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::blocking::{Prover, ProverClient, SP1Stdin};
    ///
    /// let client = ProverClient::builder().network().build();
    /// let balance = client.get_balance().unwrap();
    /// ```
    pub fn get_balance(&self) -> Result<U256> {
        crate::blocking::block_on(self.prover.get_balance())
    }

    /// Registers a program if it is not already registered.
    ///
    /// # Details
    /// * `vk`: The verifying key to use for the program.
    /// * `elf`: The elf to use for the program.
    pub fn register_program(&self, vk: &SP1VerifyingKey, elf: &[u8]) -> Result<B256> {
        crate::blocking::block_on(self.prover.register_program(vk, elf))
    }

    /// Gets the proof request parameters from the network.
    ///
    /// # Details
    /// * `mode`: The proof mode to get the parameters for.
    pub fn get_proof_request_params(
        &self,
        mode: SP1ProofMode,
    ) -> Result<GetProofRequestParamsResponse> {
        crate::blocking::block_on(self.prover.get_proof_request_params(mode))
    }

    /// Gets the status of a proof request.
    ///
    /// # Details
    /// * `request_id`: The request ID to get the status of.
    pub fn get_proof_status(
        &self,
        request_id: B256,
    ) -> Result<(GetProofRequestStatusResponse, Option<SP1ProofWithPublicValues>)> {
        crate::blocking::block_on(self.prover.get_proof_status(request_id))
    }

    /// Gets the proof request details, if available.
    ///
    /// # Details
    /// * `request_id`: The request ID to get the details of.
    pub fn get_proof_request(&self, request_id: B256) -> Result<Option<ProofRequest>> {
        crate::blocking::block_on(self.prover.get_proof_request(request_id))
    }

    /// Gets the status of a proof request with handling for timeouts and unfulfillable requests.
    ///
    /// # Details
    /// * `request_id`: The request ID to get the status of.
    /// * `remaining_timeout`: The remaining timeout for the proof request.
    pub fn process_proof_status(
        &self,
        request_id: B256,
        remaining_timeout: Option<Duration>,
    ) -> Result<(Option<SP1ProofWithPublicValues>, crate::network::proto::types::FulfillmentStatus)>
    {
        crate::blocking::block_on(self.prover.process_proof_status(request_id, remaining_timeout))
    }

    /// Cancels a proof request by updating the deadline to the current time.
    /// Only available in Mainnet mode (auction-based proving).
    pub fn cancel_request(&self, request_id: B256) -> Result<()> {
        crate::blocking::block_on(self.prover.cancel_request(request_id))
    }

    /// Waits for a proof to be generated and returns the proof. If a timeout is supplied, the
    /// function will return an error if the proof is not generated within the timeout.
    pub fn wait_proof(
        &self,
        request_id: B256,
        timeout: Option<Duration>,
        auction_timeout: Option<Duration>,
    ) -> Result<SP1ProofWithPublicValues> {
        crate::blocking::block_on(self.prover.wait_proof(request_id, timeout, auction_timeout))
    }
}
