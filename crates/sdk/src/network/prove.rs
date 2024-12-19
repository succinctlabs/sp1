//! # Network Prove
//!
//! This module provides a builder for creating a proof request to the network.

use std::time::Duration;

use anyhow::Result;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::SP1ProvingKey;

use crate::{
    utils::block_on, utils::sp1_dump, NetworkProver, SP1ProofMode, SP1ProofWithPublicValues,
};

use super::proto::network::FulfillmentStrategy;

/// A builder for creating a proof request to the network.
pub struct NetworkProveBuilder<'a> {
    pub(crate) prover: &'a NetworkProver,
    pub(crate) mode: SP1ProofMode,
    pub(crate) pk: &'a SP1ProvingKey,
    pub(crate) stdin: SP1Stdin,
    pub(crate) timeout: Option<Duration>,
    pub(crate) strategy: FulfillmentStrategy,
    pub(crate) skip_simulation: bool,
}

impl<'a> NetworkProveBuilder<'a> {
    /// Set the proof kind to [SP1ProofMode::Core] mode.
    ///
    /// # Details
    /// This is the default mode for the prover. The proofs grow linearly in size with the number
    /// of cycles.
    ///
    /// # Example
    /// ```rust,no_run
    /// let client = ProverClient::network().build();
    /// let builder = client.prove(pk, stdin)
    ///     .core()
    ///     .run();
    /// ```
    pub fn core(mut self) -> Self {
        self.mode = SP1ProofMode::Core;
        self
    }

    /// Set the proof kind to [SP1ProofMode::Compressed] mode.
    ///
    /// # Details
    /// This mode produces a proof that is of constant size, regardless of the number of cycles. It
    /// takes longer to prove than [SP1ProofMode::Core] due to the need to recursively aggregate
    /// proofs inot a single proof.
    ///
    /// # Example
    /// ```rust,no_run
    /// let client = ProverClient::network().build();
    /// let builder = client.prove(pk, stdin)
    ///     .compressed()
    ///     .run();
    /// ```
    pub fn compressed(mut self) -> Self {
        self.mode = SP1ProofMode::Compressed;
        self
    }

    /// Set the proof mode to [SP1ProofMode::Plonk] mode.
    ///
    /// # Details
    /// This mode produces a const size PLONK proof that can be verified on chain for roughly ~300k
    /// gas. This mode is useful for producing a maximally small proof that can be verified on
    /// chain. For more efficient SNARK wrapping, you can use the [SP1ProofMode::Groth16] mode but
    /// this mode is more .
    ///
    /// # Example
    /// ```rust,no_run
    /// let client = ProverClient::network().build();
    /// let builder = client.prove(pk, stdin)
    ///     .plonk()
    ///     .run();
    /// ```
    pub fn plonk(mut self) -> Self {
        self.mode = SP1ProofMode::Plonk;
        self
    }

    /// Set the proof mode to [SP1ProofMode::Groth16] mode.
    ///
    /// # Details
    /// This mode produces a Groth16 proof that can be verified on chain for roughly ~100k gas. This
    /// mode is useful for producing a proof that can be verified on chain with minimal gas.
    ///
    /// # Example
    /// ```rust,no_run
    /// let client = ProverClient::network().build();
    /// let builder = client.prove(pk, stdin)
    ///     .groth16()
    ///     .run();
    /// ```
    pub fn groth16(mut self) -> Self {
        self.mode = SP1ProofMode::Groth16;
        self
    }

    /// Set the proof mode to the given [SP1ProofMode].
    ///
    /// # Details
    /// This method is useful for setting the proof mode to a custom mode.
    ///
    /// # Example
    /// ```rust,no_run
    /// let client = ProverClient::network().build();
    /// let builder = client.prove(pk, stdin)
    ///     .mode(SP1ProofMode::Groth16)
    ///     .run();
    /// ```
    pub fn mode(mut self, mode: SP1ProofMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the timeout for the proof's generation.
    ///
    /// # Details
    /// This method sets the timeout for the proof's generation. If the proof is not generated
    /// within the timeout, the [NetworkProveBuilder::run] will return an error.
    ///
    /// # Example
    /// ```rust,no_run
    /// let client = ProverClient::network().build();
    /// let builder = client.prove(pk, stdin)
    ///     .timeout(Duration::from_secs(60))
    ///     .run();
    /// ```
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
    /// let client = ProverClient::network().build();
    /// let builder = client.prove(pk, stdin)
    ///     .skip_simulation(true)
    ///     .run();
    /// ```
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
    /// let prover = ProverClient::network()
    ///     .strategy(FulfillmentStrategy::Hosted)
    ///     .build();
    /// ```
    pub fn strategy(mut self, strategy: FulfillmentStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Run the prover with the built arguments.
    ///
    /// # Details
    /// This method will run the prover with the built arguments. If the prover fails to run, the
    /// method will return an error.
    ///
    /// # Example
    /// ```rust,no_run
    /// let client = ProverClient::network().build();
    /// let proof = client.prove(pk, stdin)
    ///     .run()
    ///     .unwrap();
    /// ```
    pub fn run(self) -> Result<SP1ProofWithPublicValues> {
        let Self { prover, mode, pk, stdin, timeout, strategy, mut skip_simulation } = self;

        // Check for deprecated environment variable
        if let Ok(val) = std::env::var("SKIP_SIMULATION") {
            eprintln!(
                "Warning: SKIP_SIMULATION environment variable is deprecated. Please use .skip_simulation() instead."
            );
            skip_simulation = matches!(val.to_lowercase().as_str(), "true" | "1");
        }

        sp1_dump(&pk.elf, &stdin);

        block_on(prover.prove_impl(pk, &stdin, mode.into(), strategy, timeout, skip_simulation))
    }

    /// Run the prover with the built arguments asynchronously.
    ///
    /// # Details
    /// This method will run the prover with the built arguments asynchronously.
    ///
    /// # Example
    /// ```rust,no_run
    /// let client = ProverClient::network().build();
    /// let proof = client.prove(pk, stdin)
    ///     .run_async()
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn run_async(self) -> Result<SP1ProofWithPublicValues> {
        let Self { prover, mode, pk, stdin, timeout, strategy, mut skip_simulation } = self;

        // Check for deprecated environment variable
        if let Ok(val) = std::env::var("SKIP_SIMULATION") {
            eprintln!(
                "Warning: SKIP_SIMULATION environment variable is deprecated. Please use .skip_simulation() instead."
            );
            skip_simulation = matches!(val.to_lowercase().as_str(), "true" | "1");
        }

        sp1_dump(&pk.elf, &stdin);

        prover.prove_impl(pk, &stdin, mode.into(), strategy, timeout, skip_simulation).await
    }
}
