//! # CPU Prover Builder
//!
//! This module provides a builder for the [CpuProver].

use sp1_prover::SP1Prover;

use super::CudaProver;

/// A builder for the [CudaProver].
///
/// The builder is used to configure the [CudaProver] before it is built.
pub struct CudaProverBuilder;

impl CudaProverBuilder {
    /// Builds a [CudaProver].
    ///
    /// # Details
    /// This method will build a [CudaProver] with the given parameters. In particular, it will
    /// build a mock prover if the `mock` flag is set.
    ///
    /// # Example
    /// ```rust,no_run
    /// let prover = ProverClient::builder().cuda().build();
    /// ```
    pub fn build(self) -> CudaProver {
        CudaProver::new(SP1Prover::new())
    }
}
