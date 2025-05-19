//! # Network Prove
//!
//! This module provides a builder for creating a proof request to the network.

use std::time::Duration;

use alloy_primitives::{Address, B256};
use anyhow::Result;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::SP1ProvingKey;

use crate::{
    utils::{block_on, sp1_dump},
    NetworkProver, SP1ProofMode, SP1ProofWithPublicValues,
};

use super::proto::network::FulfillmentStrategy;

use std::{
    future::{Future, IntoFuture},
    pin::Pin,
};

/// A builder for creating a proof request to the network.
pub struct NetworkProveBuilder<'a> {
    pub(crate) prover: &'a NetworkProver,
    pub(crate) mode: SP1ProofMode,
    pub(crate) pk: &'a SP1ProvingKey,
    pub(crate) stdin: SP1Stdin,
    pub(crate) timeout: Option<Duration>,
    pub(crate) strategy: FulfillmentStrategy,
    pub(crate) skip_simulation: bool,
    pub(crate) cycle_limit: Option<u64>,
    pub(crate) gas_limit: Option<u64>,
    pub(crate) tee_2fa: bool,
    pub(crate) min_auction_period: u64,
    pub(crate) whitelist: Vec<Address>,
}

impl NetworkProveBuilder<'_> {
    /// Set the proof kind to [`SP1ProofMode::Core`] mode.
    ///
    /// # Details
    /// This is the default mode for the prover. The proofs grow linearly in size with the number
    /// of cycles.
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
    /// let builder = client.prove(&pk, &stdin).core().run();
    /// ```
    #[must_use]
    pub fn core(mut self) -> Self {
        self.mode = SP1ProofMode::Core;
        self
    }

    /// Set the proof kind to [`SP1ProofMode::Compressed`] mode.
    ///
    /// # Details
    /// This mode produces a proof that is of constant size, regardless of the number of cycles. It
    /// takes longer to prove than [`SP1ProofMode::Core`] due to the need to recursively aggregate
    /// proofs into a single proof.
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
    /// let builder = client.prove(&pk, &stdin).compressed().run();
    /// ```
    #[must_use]
    pub fn compressed(mut self) -> Self {
        self.mode = SP1ProofMode::Compressed;
        self
    }

    /// Set the proof mode to [`SP1ProofMode::Plonk`] mode.
    ///
    /// # Details
    /// This mode produces a const size PLONK proof that can be verified on chain for roughly ~300k
    /// gas. This mode is useful for producing a maximally small proof that can be verified on
    /// chain. For more efficient SNARK wrapping, you can use the [`SP1ProofMode::Groth16`] mode but
    /// this mode is more .
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
    /// let builder = client.prove(&pk, &stdin).plonk().run();
    /// ```
    #[must_use]
    pub fn plonk(mut self) -> Self {
        self.mode = SP1ProofMode::Plonk;
        self
    }

    /// Set the proof mode to [`SP1ProofMode::Groth16`] mode.
    ///
    /// # Details
    /// This mode produces a Groth16 proof that can be verified on chain for roughly ~100k gas. This
    /// mode is useful for producing a proof that can be verified on chain with minimal gas.
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
    /// let builder = client.prove(&pk, &stdin).groth16().run();
    /// ```
    #[must_use]
    pub fn groth16(mut self) -> Self {
        self.mode = SP1ProofMode::Groth16;
        self
    }

    /// Set the proof mode to the given [`SP1ProofMode`].
    ///
    /// # Details
    /// This method is useful for setting the proof mode to a custom mode.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Prover, ProverClient, SP1ProofMode, SP1Stdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().network().build();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).mode(SP1ProofMode::Groth16).run();
    /// ```
    #[must_use]
    pub fn mode(mut self, mode: SP1ProofMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the timeout for the proof's generation.
    ///
    /// # Details
    /// This method sets the timeout for the proof's generation. If the proof is not generated
    /// within the timeout, the [`NetworkProveBuilder::run`] will return an error.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
    /// use std::time::Duration;
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().network().build();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).timeout(Duration::from_secs(60)).run();
    /// ```
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set whether to skip the local execution simulation step.
    ///
    /// # Details
    /// This method sets whether to skip the local execution simulation step. If the simulation
    /// step is skipped, the request will sent to the network without verifying that the execution
    /// succeeds locally (without generating a proof). This feature is recommended for users who
    /// want to optimize the latency of the proof generation on the network.
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
    /// let builder = client.prove(&pk, &stdin).skip_simulation(true).run();
    /// ```
    #[must_use]
    pub fn skip_simulation(mut self, skip_simulation: bool) -> Self {
        self.skip_simulation = skip_simulation;
        self
    }

    /// Sets the fulfillment strategy for the client.
    ///
    /// # Details
    /// The strategy determines how the client will fulfill requests.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{network::FulfillmentStrategy, Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().network().build();
    /// let (pk, vk) = client.setup(elf);
    /// let proof = client.prove(&pk, &stdin).strategy(FulfillmentStrategy::Hosted).run().unwrap();
    /// ```
    #[must_use]
    pub fn strategy(mut self, strategy: FulfillmentStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Sets the cycle limit for the proof request.
    ///
    /// # Details
    /// The cycle limit determines the maximum number of cycles that the program should take to
    /// execute. By default, the cycle limit is determined by simulating the program locally.
    /// However, you can manually set it if you know the exact cycle count needed and want to skip
    /// the simulation step locally.
    ///
    /// The cycle limit ensures that a prover on the network will stop generating a proof once the
    /// cycle limit is reached, which prevents denial of service attacks.
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
    /// let proof = client
    ///     .prove(&pk, &stdin)
    ///     .cycle_limit(1_000_000) // Set 1M cycle limit.
    ///     .skip_simulation(true) // Skip simulation since the limit is set manually.
    ///     .run()
    ///     .unwrap();
    /// ```
    #[must_use]
    pub fn cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.cycle_limit = Some(cycle_limit);
        self
    }

    /// Sets the gas limit for the proof request.
    ///
    /// # Details
    /// The gas limit determines the maximum amount of gas that the program should consume. By
    /// default, the gas limit is determined by simulating the program locally. However, you can
    /// manually set it if you know the exact gas count needed and want to skip the simulation
    /// step locally.
    ///
    /// The gas limit ensures that a prover on the network will stop generating a proof once the
    /// gas limit is reached, which prevents denial of service attacks.
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
    /// let proof = client
    ///     .prove(&pk, &stdin)
    ///     .gas_limit(1_000_000) // Set 1M gas limit.
    ///     .skip_simulation(true) // Skip simulation since the limit is set manually.
    ///     .run()
    ///     .unwrap();
    /// ```
    #[must_use]
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }

    /// Set the TEE proof type to use.
    ///
    /// # Details
    /// This method sets the TEE proof type to use.
    ///
    /// # Example
    /// ```rust,no_run
    /// fn create_proof() {
    ///     use sp1_sdk::{Prover, ProverClient, SP1Stdin};
    ///
    ///     let elf = &[1, 2, 3];
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build();
    ///     let (pk, vk) = client.setup(elf);
    ///     let builder = client.prove(&pk, &stdin).tee_2fa().run();
    /// }
    /// ```
    #[must_use]
    pub fn tee_2fa(mut self) -> Self {
        self.tee_2fa = true;
        self
    }

    /// Set the minimum auction period for the proof request in seconds.
    ///
    /// # Details
    /// This method sets the minimum auction period for the proof request. Only relevant if the
    /// strategy is set to [`FulfillmentStrategy::Auction`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
    /// use std::time::Duration;
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().network().build();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).min_auction_period(60).run();
    /// ```
    #[must_use]
    pub fn min_auction_period(mut self, min_auction_period: u64) -> Self {
        self.min_auction_period = min_auction_period;
        self
    }

    /// Set the whitelist for the proof request.
    ///
    /// # Details
    /// Only provers specified in the whitelist will be able to bid and prove on the request. Only
    /// relevant if the strategy is set to [`FulfillmentStrategy::Auction`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use alloy_primitives::Address;
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
    /// use std::str::FromStr;
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().network().build();
    /// let (pk, vk) = client.setup(elf);
    /// let whitelist = vec![Address::from_str("0x123").unwrap(), Address::from_str("0x456").unwrap()];
    /// let builder = client.prove(&pk, &stdin).whitelist(whitelist).run();
    /// ```
    #[must_use]
    pub fn whitelist(mut self, whitelist: Vec<Address>) -> Self {
        self.whitelist = whitelist;
        self
    }

    /// Request a proof from the prover network.
    ///
    /// # Details
    /// This method will request a proof from the prover network. If the prover fails to request
    /// a proof, the method will return an error. It will not wait for the proof to be generated.
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
    /// let request_id = client.prove(&pk, &stdin).request().unwrap();
    /// ```
    pub fn request(self) -> Result<B256> {
        block_on(self.request_async())
    }

    /// Request a proof from the prover network asynchronously.
    ///
    /// # Details
    /// This method will request a proof from the prover network asynchronously. If the prover fails
    /// to request a proof, the method will return an error. It will not wait for the proof to be
    /// generated.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = &[1, 2, 3];
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build();
    ///     let (pk, vk) = client.setup(elf);
    ///     let request_id = client.prove(&pk, &stdin).request_async().await.unwrap();
    /// })
    /// ```
    pub async fn request_async(self) -> Result<B256> {
        self.prover
            .request_proof_impl(
                self.pk,
                &self.stdin,
                self.mode,
                self.strategy,
                self.timeout,
                self.skip_simulation,
                self.cycle_limit,
                self.gas_limit,
                self.min_auction_period,
                self.whitelist,
            )
            .await
    }

    /// Run the prover with the built arguments.
    ///
    /// # Details
    /// This method will run the prover with the built arguments. If the prover fails to run, the
    /// method will return an error.
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
    /// let proof = client.prove(&pk, &stdin).run().unwrap();
    /// ```
    pub fn run(self) -> Result<SP1ProofWithPublicValues> {
        block_on(self.run_async())
    }

    /// Run the prover with the built arguments asynchronously.
    ///
    /// # Details
    /// This method will run the prover with the built arguments asynchronously.
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
    /// let proof = client.prove(&pk, &stdin).run_async();
    /// ```
    pub async fn run_async(mut self) -> Result<SP1ProofWithPublicValues> {
        // Check for deprecated environment variable
        if let Ok(val) = std::env::var("SKIP_SIMULATION") {
            eprintln!(
                "Warning: SKIP_SIMULATION environment variable is deprecated. Please use .skip_simulation() instead."
            );
            self.skip_simulation = matches!(val.to_lowercase().as_str(), "true" | "1");
        }

        sp1_dump(&self.pk.elf, &self.stdin);

        self.prover
            .prove_impl(
                self.pk,
                &self.stdin,
                self.mode,
                self.strategy,
                self.timeout,
                self.skip_simulation,
                self.cycle_limit,
                self.gas_limit,
                self.tee_2fa,
                self.min_auction_period,
                self.whitelist,
            )
            .await
    }
}

impl<'a> IntoFuture for NetworkProveBuilder<'a> {
    type Output = Result<SP1ProofWithPublicValues>;

    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.run_async())
    }
}
