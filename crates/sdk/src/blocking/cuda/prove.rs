// //! # CUDA Proving
// //!
// //! This module provides a builder for proving a program on the CUDA.
use sp1_cuda::CudaClientError;

use super::CudaProver;
use crate::{
    blocking::{
        block_on,
        prover::{BaseProveRequest, ProveRequest},
    },
    utils::proof_mode,
    SP1ProofWithPublicValues,
};

/// A builder for proving a program on the CUDA.
///
/// This builder provides a typed interface for configuring the SP1 RISC-V prover. The builder is
/// used for only the [`crate::cuda::CudaProver`] client type.
pub struct CudaProveRequest<'a> {
    pub(crate) base: BaseProveRequest<'a, CudaProver>,
}

impl<'a> ProveRequest<'a, CudaProver> for CudaProveRequest<'a> {
    fn base(&mut self) -> &mut BaseProveRequest<'a, CudaProver> {
        &mut self.base
    }

    fn run(self) -> Result<SP1ProofWithPublicValues, CudaClientError> {
        let BaseProveRequest { prover, pk, stdin, mode, mut context_builder } = self.base;
        tracing::info!(mode = ?mode, "starting proof generation");
        let context = context_builder.build();
        Ok(block_on(prover.prover.prove_with_mode(pk, stdin, context, proof_mode(mode)))?.into())
    }
}
