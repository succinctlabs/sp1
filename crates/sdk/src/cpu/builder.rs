//! # CPU Prover Builder
//!
//! This module provides a builder for the [CpuProver].

use super::CpuProver;

/// A builder for the [CpuProver].
///
/// The builder is used to configure the [CpuProver] before it is built.
pub struct CpuProverBuilder {
    pub(crate) mock: bool,
}

impl CpuProverBuilder {
    /// Builds a [CpuProver].
    ///
    /// # Details
    /// This method will build a [CpuProver] with the given parameters. In particular, it will
    /// build a mock prover if the `mock` flag is set.
    ///
    /// # Example
    /// ```rust,no_run
    /// let prover = ProverClient::builder().mock().build();
    /// ```
    pub fn build(self) -> CpuProver {
        if self.mock { CpuProver::mock() } else { CpuProver::new() }
    }
}
