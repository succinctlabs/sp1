//! # SP1 CUDA Prover
//!
//! A prover that uses the CUDA to execute and prove programs.

/// The builder for the CUDA prover.
pub mod builder;
/// The CUDA prove request type.
pub mod prove;

use crate::{
    prover::{BaseProveRequest, Prover, SendFutureResult},
    ProvingKey,
};

use prove::CudaProveRequest;
use sp1_core_machine::io::SP1Stdin;
use sp1_cuda::{CudaClientError, CudaProver as CudaProverImpl, CudaProvingKey};
use sp1_primitives::Elf;
use sp1_prover::{
    worker::{SP1LightNode, SP1NodeCore},
    SP1VerifyingKey,
};

/// A prover that uses the CPU for execution and the CUDA for proving.
#[derive(Clone)]
pub struct CudaProver {
    pub(crate) node: SP1LightNode,
    pub(crate) prover: CudaProverImpl,
}

impl Prover for CudaProver {
    type ProvingKey = CudaProvingKey;
    type Error = CudaClientError;
    type ProveRequest<'a> = CudaProveRequest<'a>;

    fn inner(&self) -> &SP1NodeCore {
        self.node.inner()
    }

    fn setup(&self, elf: Elf) -> impl SendFutureResult<Self::ProvingKey, Self::Error> {
        let machine = self.node.inner().machine().clone();
        async move { self.prover.setup_with_machine(elf, machine).await }
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        CudaProveRequest { base: BaseProveRequest::new(self, pk, stdin) }
    }
}

impl ProvingKey for CudaProvingKey {
    fn elf(&self) -> &Elf {
        self.elf()
    }

    fn verifying_key(&self) -> &SP1VerifyingKey {
        self.verifying_key()
    }
}
