//! # Network Prove (Blocking)
//!
//! This module provides a blocking builder for creating a proof request to the network.

use std::time::Duration;

use alloy_primitives::{Address, B256};
use anyhow::Result;

use super::NetworkProver;
use crate::{
    blocking::prover::{BaseProveRequest, ProveRequest},
    network::{proto::types::FulfillmentStrategy, validation},
    SP1ProofWithPublicValues,
};

/// A blocking builder for creating a proof request to the network.
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
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set whether to skip the local execution simulation step.
    #[must_use]
    pub fn skip_simulation(mut self, skip_simulation: bool) -> Self {
        self.skip_simulation = skip_simulation;
        self
    }

    /// Sets the fulfillment strategy for the client.
    #[must_use]
    pub fn strategy(mut self, strategy: FulfillmentStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Sets the cycle limit for the proof request.
    #[must_use]
    pub fn cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.cycle_limit = Some(cycle_limit);
        self
    }

    /// Sets the gas limit for the proof request.
    #[must_use]
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }

    /// Set the TEE proof type to use.
    #[must_use]
    #[cfg(feature = "tee-2fa")]
    pub fn tee_2fa(mut self) -> Self {
        self.tee_2fa = true;
        self
    }

    /// Set the minimum auction period for the proof request in seconds.
    #[must_use]
    pub fn min_auction_period(mut self, min_auction_period: u64) -> Self {
        self.min_auction_period = min_auction_period;
        self
    }

    /// Set the whitelist for the proof request.
    #[must_use]
    pub fn whitelist(mut self, whitelist: Option<Vec<Address>>) -> Self {
        self.whitelist = whitelist;
        self
    }

    /// Set the auctioneer for the proof request.
    #[must_use]
    pub fn auctioneer(mut self, auctioneer: Address) -> Self {
        self.auctioneer = Some(auctioneer);
        self
    }

    /// Set the executor for the proof request.
    #[must_use]
    pub fn executor(mut self, executor: Address) -> Self {
        self.executor = Some(executor);
        self
    }

    /// Set the verifier for the proof request.
    #[must_use]
    pub fn verifier(mut self, verifier: Address) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Set the treasury for the proof request.
    #[must_use]
    pub fn treasury(mut self, treasury: Address) -> Self {
        self.treasury = Some(treasury);
        self
    }

    /// Sets the max price per PGU for the proof request.
    #[must_use]
    pub fn max_price_per_pgu(mut self, max_price_per_pgu: u64) -> Self {
        self.max_price_per_pgu = Some(max_price_per_pgu);
        self
    }

    /// Sets the auction timeout for the proof request.
    #[must_use]
    pub fn auction_timeout(mut self, auction_timeout: Duration) -> Self {
        self.auction_timeout = Some(auction_timeout);
        self
    }

    /// Request a proof from the prover network without waiting for it to be generated.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = Elf::Static(&[1, 2, 3]);
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().network().build();
    /// let pk = client.setup(elf).unwrap();
    /// let request_id = client.prove(&pk, stdin).request().unwrap();
    /// ```
    pub fn request(self) -> Result<B256> {
        crate::blocking::block_on(self.base.prover.prover.request_proof_impl(
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
        ))
    }
}

impl<'a> ProveRequest<'a, NetworkProver> for NetworkProveBuilder<'a> {
    fn base(&mut self) -> &mut BaseProveRequest<'a, NetworkProver> {
        &mut self.base
    }

    fn run(mut self) -> Result<SP1ProofWithPublicValues> {
        validation::validate_strategy_compatibility(
            self.base.prover.prover.network_mode(),
            self.strategy,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        if let Ok(val) = std::env::var("SKIP_SIMULATION") {
            tracing::warn!(
                "SKIP_SIMULATION environment variable is deprecated. Please use .skip_simulation() instead."
            );
            self.skip_simulation = matches!(val.to_lowercase().as_str(), "true" | "1");
        }

        crate::utils::sp1_dump(&self.base.pk.elf, &self.base.stdin);

        tracing::info!(mode = ?self.base.mode, "requesting proof from network");
        crate::blocking::block_on(self.base.prover.prover.prove_impl(
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
        ))
    }
}
