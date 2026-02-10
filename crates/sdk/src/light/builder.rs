//! # Light Prover Builder
//!
//! This module provides a builder for the [`LightProver`].

use super::LightProver;
use sp1_core_executor::SP1CoreOpts;

/// A builder for the [`LightProver`].
///
/// The builder is used to configure the [`LightProver`] before it is built.
pub struct LightProverBuilder {
    /// Optional core options to configure the prover.
    core_opts: Option<SP1CoreOpts>,
}

impl Default for LightProverBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl LightProverBuilder {
    /// Creates a new [`LightProverBuilder`] with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self { core_opts: None }
    }

    /// Sets the core options for the prover.
    #[must_use]
    pub fn core_opts(mut self, opts: SP1CoreOpts) -> Self {
        self.core_opts = Some(opts);
        self
    }

    /// Sets the core options for the prover (alias for `core_opts`).
    #[must_use]
    pub fn with_opts(self, opts: SP1CoreOpts) -> Self {
        self.core_opts(opts)
    }

    /// Builds a [`LightProver`].
    #[must_use]
    pub async fn build(self) -> LightProver {
        match self.core_opts {
            Some(opts) => LightProver::new_with_opts(opts).await,
            None => LightProver::new().await,
        }
    }
}
