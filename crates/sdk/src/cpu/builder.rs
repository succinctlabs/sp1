//! # CPU Prover Builder
//!
//! This module provides a builder for the [`CpuProver`].

use crate::utils::setup_memory_usage_monitoring;

use super::CpuProver;

/// A builder for the [`CpuProver`].
///
/// The builder is used to configure the [`CpuProver`] before it is built.
pub struct CpuProverBuilder {
    pub(crate) mock: bool,
}

impl CpuProverBuilder {
    /// Builds a [`CpuProver`].
    ///
    /// # Details
    /// This method will build a [`CpuProver`] with the given parameters. In particular, it will
    /// build a mock prover if the `mock` flag is set.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().mock().build();
    /// ```
    #[must_use]
    pub fn build(self) -> CpuProver {
        if self.mock {
            CpuProver::mock()
        } else {
            setup_memory_usage_monitoring();
            CpuProver::new()
        }
    }
}
