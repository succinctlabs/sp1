//! # Network Prove
//!
//! This module provides a builder for creating a proof request to the network.

use std::time::Duration;

use alloy_primitives::{Address, B256};
use anyhow::Result;

use crate::{
    prover::BaseProveRequest, utils::sp1_dump, NetworkProver, ProveRequest,
    SP1ProofWithPublicValues,
};

use super::{proto::types::FulfillmentStrategy, validation};

use std::{
    future::{Future, IntoFuture},
    pin::Pin,
};

/// A builder for creating a proof request to the network.
pub struct NetworkProveBuilder<'a> {
    pub(crate) base: BaseProveRequest<'a, NetworkProver>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) strategy: FulfillmentStrategy,
    pub(crate) skip_simulation: bool,
    pub(crate) cycle_limit: Option<u64>,
    pub(crate) gas_limit: Option<u64>,
    pub(crate) tee_2fa: bool,
    pub(crate) min_auction_period: u64,
    pub(crate) whitelist: Option<Vec<Address>>,
    pub(crate) auctioneer: Option<Address>,
    pub(crate) executor: Option<Address>,
    pub(crate) verifier: Option<Address>,
    pub(crate) treasury: Option<Address>,
    pub(crate) max_price_per_pgu: Option<u64>,
    pub(crate) auction_timeout: Option<Duration>,
}

impl NetworkProveBuilder<'_> {
    /// Set the timeout for the proof's generation.
    ///
    /// # Details
    /// This method sets the timeout for the proof's generation. If the proof is not generated
    /// within the timeout, the [`NetworkProveBuilder::run`] will return an error.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    /// use std::time::Duration;
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).timeout(Duration::from_secs(60)).await.unwrap();
    /// });
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
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).skip_simulation(true).await.unwrap();
    /// });
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
    /// use sp1_sdk::{network::FulfillmentStrategy, Elf, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).strategy(FulfillmentStrategy::Hosted).await.unwrap();
    /// });
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
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client
    ///         .prove(&pk, stdin)
    ///         .cycle_limit(1_000_000) // Set 1M cycle limit.
    ///         .skip_simulation(true) // Skip simulation since the limit is set manually.
    ///         .await
    ///         .unwrap();
    /// });
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
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client
    ///         .prove(&pk, stdin)
    ///         .gas_limit(1_000_000) // Set 1M gas limit.
    ///         .skip_simulation(true) // Skip simulation since the limit is set manually.
    ///         .await
    ///         .unwrap();
    /// });
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
    /// async fn create_proof() {
    ///     use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    ///
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client.prove(&pk, stdin).tee_2fa().await.unwrap();
    /// }
    /// ```
    #[must_use]
    #[cfg(feature = "tee-2fa")]
    pub fn tee_2fa(mut self) -> Self {
        self.tee_2fa = true;
        self
    }

    /// Set the minimum auction period for the proof request in seconds.
    ///
    /// # Details
    /// The minimum auction period determines how long to wait before settling the auction for the
    /// proof request. The auction only settles after both the minimum time has passed and at least
    /// one bid is received. If a value is not specified, the default is 1 second.
    ///
    /// Only relevant if the strategy is set to [`FulfillmentStrategy::Auction`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    /// use std::time::Duration;
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let builder = client.prove(&pk, stdin).min_auction_period(60).await;
    /// });
    /// ```
    #[must_use]
    pub fn min_auction_period(mut self, min_auction_period: u64) -> Self {
        self.min_auction_period = min_auction_period;
        self
    }

    /// Set the whitelist for the proof request.
    ///
    /// # Details
    /// The whitelist determines which provers are allowed to bid on the proof request.
    ///
    /// Only relevant if the strategy is set to [`FulfillmentStrategy::Auction`].
    ///
    /// If whitelist is `None` when requesting a proof, a set of recently reliable provers will be
    /// used.
    ///
    /// # Example
    /// ```rust,no_run
    /// use alloy_primitives::Address;
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    /// use std::str::FromStr;
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let whitelist =
    ///         vec![Address::from_str("0x123").unwrap(), Address::from_str("0x456").unwrap()];
    ///     let proof = client.prove(&pk, stdin).whitelist(Some(whitelist)).await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn whitelist(mut self, whitelist: Option<Vec<Address>>) -> Self {
        self.whitelist = whitelist;
        self
    }

    /// Set the auctioneer for the proof request.
    ///
    /// # Details
    /// Only the specified auctioneer will be able to manage the auction for this request.
    ///
    /// Only relevant if the strategy is set to [`FulfillmentStrategy::Auction`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use alloy_primitives::Address;
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    /// use std::str::FromStr;
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let auctioneer = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
    ///     let proof = client.prove(&pk, stdin).auctioneer(auctioneer).await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn auctioneer(mut self, auctioneer: Address) -> Self {
        self.auctioneer = Some(auctioneer);
        self
    }

    /// Set the executor for the proof request.
    ///
    /// # Details
    /// Only the specified executor will be able to fulfill this request. This is useful for
    /// whitelisting specific provers for private or prioritized jobs.
    ///
    /// # Example
    /// ```rust,no_run
    /// use alloy_primitives::Address;
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    /// use std::str::FromStr;
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let executor = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
    ///     let proof = client.prove(&pk, stdin).executor(executor).await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn executor(mut self, executor: Address) -> Self {
        self.executor = Some(executor);
        self
    }

    /// Set the verifier for the proof request.
    ///
    /// # Details
    /// Only the specified verifier will be able to verify the proof. Only relevant if the mode is
    /// not [`SP1ProofMode::Compressed`], as this mode will be verified within the `VApp`.
    ///
    /// # Example
    /// ```rust,no_run
    /// use alloy_primitives::Address;
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    /// use std::str::FromStr;
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let verifier = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
    ///     let proof = client.prove(&pk, stdin).verifier(verifier).await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn verifier(mut self, verifier: Address) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Set the treasury for the proof request.
    ///
    /// # Details
    /// The treasury is the address that will receive the protocol fee portion of the proof request
    /// reward when it is fulfilled.
    ///
    /// # Example
    /// ```rust,no_run
    /// use alloy_primitives::Address;
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    /// use std::str::FromStr;
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let treasury = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
    ///     let proof = client.prove(&pk, stdin).treasury(treasury).await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn treasury(mut self, treasury: Address) -> Self {
        self.treasury = Some(treasury);
        self
    }

    /// Sets the max price per PGU for the proof request.
    ///
    /// # Details
    /// The max price per PGU (prover gas unit) lets you specify the maximum amount of PROVE
    /// you are willing to pay per PGU, protecting you from unexpected price escalation. If a value
    /// is not specified, a default value will be used.
    ///
    /// Only relevant if the strategy is set to [`FulfillmentStrategy::Auction`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use alloy_primitives::Address;
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    /// use std::str::FromStr;
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let treasury = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
    ///     let proof = client
    ///         .prove(&pk, stdin)
    ///         .max_price_per_pgu(1_000_000_000_000_000_000u64) // Set 1 PROVE (18 decimals).
    ///         .await
    ///         .unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn max_price_per_pgu(mut self, max_price_per_pgu: u64) -> Self {
        self.max_price_per_pgu = Some(max_price_per_pgu);
        self
    }

    /// Sets the auction timeout for the proof request.
    ///
    /// # Details
    /// The auction timeout determines how long to wait for a prover to bid on the proof request.
    /// If no provers bid on the request within this timeout, the proof request will be canceled. If
    /// a value is not specified, the default is 30 seconds.
    ///
    /// Only relevant if the strategy is set to [`FulfillmentStrategy::Auction`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    /// use std::time::Duration;
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let proof = client
    ///         .prove(&pk, stdin)
    ///         .auction_timeout(Duration::from_secs(60)) // Wait 60 seconds for a prover to pick up the request.
    ///         .await
    ///         .unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn auction_timeout(mut self, auction_timeout: Duration) -> Self {
        self.auction_timeout = Some(auction_timeout);
        self
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
    /// use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let client = ProverClient::builder().network().build().await;
    ///     let pk = client.setup(elf).await.unwrap();
    ///     let request_id = client.prove(&pk, stdin).request().await.unwrap();
    /// })
    /// ```
    pub async fn request(self) -> Result<B256> {
        self.base
            .prover
            .request_proof_impl(
                self.base.pk,
                &self.base.stdin,
                self.base.mode,
                self.strategy,
                self.timeout,
                self.skip_simulation,
                self.cycle_limit,
                self.gas_limit,
                self.min_auction_period,
                self.whitelist,
                self.auctioneer,
                self.executor,
                self.verifier,
                self.treasury,
                self.max_price_per_pgu,
            )
            .await
    }
}

impl<'a> ProveRequest<'a, NetworkProver> for NetworkProveBuilder<'a> {
    fn base(&mut self) -> &mut BaseProveRequest<'a, NetworkProver> {
        &mut self.base
    }
}

impl<'a> IntoFuture for NetworkProveBuilder<'a> {
    type Output = Result<SP1ProofWithPublicValues>;

    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(mut self) -> Self::IntoFuture {
        Box::pin(async move {
            // Validate strategy compatibility with network mode before proceeding.
            validation::validate_strategy_compatibility(
                self.base.prover.network_mode(),
                self.strategy,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;

            // Check for deprecated environment variable.
            if let Ok(val) = std::env::var("SKIP_SIMULATION") {
                tracing::warn!(
                "SKIP_SIMULATION environment variable is deprecated. Please use .skip_simulation() instead."
            );
                self.skip_simulation = matches!(val.to_lowercase().as_str(), "true" | "1");
            }

            sp1_dump(&self.base.pk.elf, &self.base.stdin);

            tracing::info!(mode = ?self.base.mode, "requesting proof from network");
            self.base
                .prover
                .prove_impl(
                    self.base.pk,
                    &self.base.stdin,
                    self.base.mode,
                    self.strategy,
                    self.timeout,
                    self.skip_simulation,
                    self.cycle_limit,
                    self.gas_limit,
                    self.tee_2fa,
                    self.min_auction_period,
                    self.whitelist,
                    self.auctioneer,
                    self.executor,
                    self.verifier,
                    self.treasury,
                    self.max_price_per_pgu,
                    self.auction_timeout,
                )
                .await
        })
    }
}
